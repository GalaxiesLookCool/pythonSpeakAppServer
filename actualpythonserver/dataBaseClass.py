import json
import logging
import sqlite3
import string
import sys
import time
import threading
import random

from sqlite3 import Error
from hashlib import sha256
from default_image import DEFAULT_CHAT_IMAGE

TOKEN_LENGTH = 20

log = logging.getLogger(__name__)

def print(*args, **kwargs):
    pass

def create_connection(db_file):
    """ create a database connection to the SQLite database
    specified by db_file
    :param db_file: database file
    :return: None
    """
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(sqlite3.version)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        conn.commit()
    except Error as e:
        print(e)


class LockableSqliteConnection:
    TOKEN_LENGTH = 20
    MAX_QUERY_LENGTH = 1000000

    def get_user_emails_ids_by_filter(self, search_filter: str) -> list:
        """
        returns a list of all users where their email includes the filter
        :param search_filter: the search filter to apply
        returns the queried list
        """
        matches_to_return = []
        exact_sql_comm = "SELECT id, email, uname FROM users WHERE email=? AND enabled=1"
        exact_match = self.query(exact_sql_comm, (search_filter,))
        added_ids= []
        if len(exact_match) > 0:
            for user_data in exact_match:
                if user_data[0] not in added_ids:
                    added_ids.append(user_data[0])
                    matches_to_return.append({"id": user_data[0], "email": user_data[1], "uname": user_data[2]})
        rough_match_comm = "SELECT id, email, uname FROM users WHERE instr(email, ?) =1 AND enabled=1 ORDER BY email ASC LIMIT 10000 "
        rough_matches = self.query(rough_match_comm, (search_filter, ))#will get everyone
        for user_data in rough_matches:
            if user_data[0] not in added_ids:
                added_ids.append(user_data[0])
                matches_to_return.append({"id": user_data[0], "email": user_data[1], "uname": user_data[2]})
        return matches_to_return


    def is_exist_oneonone_chat(self, user_id1: int, user_id2: int) -> bool:
        """
        Checks if a one on one chat for these 2 specific users exists in the db
        :param user_id1: user id of one user
        :param user_id2: user id of second user
        :return: True if exists, False otherwise
        """
        sql_comm = """SELECT * FROM chats WHERE type=2 AND groupmembersbyid=?"""
        return (len(self.query(sql_comm, (json.dumps([user_id1, user_id2]),))) > 0) or (len(self.query(sql_comm, (json.dumps([user_id2, user_id1]),))) > 0)

    def create_one_on_one_chat(self, user_id1: int, user_id2: int) -> int:
        """
        Creates a one on one chat for these 2 specific users in the db
        :param user_id1: user id of first user
        :param user_id2: user id of second user
        :return: returns the id of the new chat
        """
        sql_comm = """INSERT INTO chats (name,groupmembersbyid,type) VALUES ("",?,?)"""
        new_id = self.query(sql_comm, (json.dumps([user_id1, user_id2]), 2))
        return new_id


    def save_new_msg(self, group_id: str, sender_id: str, text_content: str, time_sent: str, msg_type: str,
                     attachments: list) -> int:
        """
        Saves a new message to the database
        :param group_id: group id
        :param sender_id: sender id
        :param text_content: text content
        :param time_sent: timesnet
        :param msg_type: msg type
        :param attachments: attachments
        :return: new message id
        """
        attachments = json.dumps(attachments)
        print(attachments)
        sql_query = f"""INSERT INTO chat{group_id} (senderid, textcontent, timesent, type, attachments) VALUES (?,?,?,?,?)"""
        new_id = self.query(sql_query, (sender_id, text_content, time_sent, msg_type, attachments))
        return new_id



    def update_user_chats(self, user_id: str, new_chat_id: str):
        """
        Updates the user chats in db (users table)
        :param user_id: user id
        :param new_chat_id: new chat id
        :return: None
        """
        fetch_ids_query = """SELECT arrayOfChats FROM users WHERE id=?"""
        chat_ids = json.loads(self.query(fetch_ids_query, (user_id,))[0][0])
        chat_ids.append(new_chat_id)
        update_query = """UPDATE users SET arrayOfChats=? WHERE id=?"""
        self.query(update_query, (json.dumps(chat_ids), user_id))

    def make_new_chat(self, group_name: str, group_picture: str, group_type: str, group_members: list[str], creator_id : int) -> int:
        """
        Creates a new chat in db (new table and new row)
        :param group_name: group name
        :param group_picture: group picture
        :param group_type: group type
        :param group_members: group members
        :param creator_id: the id of the group creator
        :return: new chat id
        """
        create_row_query = """INSERT INTO chats (name, picture, type, groupmembersbyid, metadata) VALUES (?,?,?,?,?)"""
        new_id = self.query(create_row_query, (group_name, group_picture, group_type, json.dumps(group_members), json.dumps({"admins" : [creator_id]})))
        new_table_command = f"""CREATE TABLE IF NOT EXISTS chat{new_id} (msgid integer PRIMARY KEY, senderid integer, lastedited text, textcontent text, timesent text, type text, attachments text, {', '.join(list(map(lambda user_id: "user" + str(user_id) + " integer DEFAULT 0", group_members)))})"""
        self.query(new_table_command)
        return new_id

    def is_group_exists(self, group_id : str) -> bool:
        """
        Checks if a group exists in the db
        :param group_id: group id
        :return: True if exists, False otherwise
        """
        sql_query = """SELECT * FROM chats WHERE id=?"""
        return len(self.query(sql_query, (group_id,))) > 0

    def get_token_ip(self, token : str) -> str | None:
        """
        gets the ip that is associated with the token
        :param token: token to search
        :return: the ip
        """
        query = """SELECT ip FROM tokens WHERE token=?"""
        data = self.query(query, (token,))
        if len(data) == 0:
            return None
        return self.query(query, (token,))[0][0]



    def get_group_participants(self, group_id: str) -> list:
        """
        Gets the group participants
        :param group_id: group id
        :return: list of participants by id
        """
        print(f"group id is {group_id}")
        sql_query = """SELECT groupmembersbyid FROM  chats WHERE id=?"""
        print(self.query(sql_query, (group_id,)))
        return json.loads(self.query(sql_query, (group_id,))[0][0])

    def fetch_msgs(self, group_id: str, lower_bound: str | int, upper_bound: str | int) -> list[dict]:
        """
        Fetches messages from the db
        :param group_id: group id
        :param lower_bound: lower bound
        :param upper_bound: upper bound
        :return: list of messages in between the bounds

        database structure: msgid integer PRIMARY KEY, senderid integer, lastedited text, textcontent text, timesent text, type text, attachments text
        """
        if str(lower_bound) == "0" and str(upper_bound) == "0":
            sql_query = f"""SELECT * FROM chat{group_id} ORDER BY msgid DESC LIMIT 20"""
            sql_data = self.query(sql_query, tuple())
        else:
            sql_query = f"""SELECT * FROM chat{group_id} WHERE msgid BETWEEN ? AND ? ORDER BY msgid DESC"""
            sql_data = self.query(sql_query, (lower_bound, upper_bound,))
        return_list = list()
        group_participants = self.get_group_participants(group_id)
        print("going to print messages row")
        for row in sql_data:
            print(row)
            basic_dict = {"msgid": row[0], "senderid": row[1], "lastedited": row[2],"textcontent": row[3], "timesent": row[4],
                          "type": row[5], "attachments": json.loads(row[6]), "read_receipts" : dict()}
            for participant in group_participants:
                basic_dict["read_receipts"][participant] = row[group_participants.index(participant) + 7]
            return_list.append(basic_dict)
        return return_list

    def update_user_info(self, uid : str, new_name : str, new_b64 : str) -> int:
        """
        Updates the user info in the db
        :param uid: user id
        :param new_name: new name
        :param new_b64: new picture
        :return: returns the user id
        """
        query = """UPDATE users SET uname=? ,picture=? WHERE id=?"""
        return self.query(query, (new_name, new_b64, uid))

    def get_safe_user_data(self, userid: str) -> dict:
        """
        Gets the safe user data from the db
        :param userid: user id
        :return: user data (name, pfp, email, last_seen)
        """
        sql_query = """SELECT uname, picture, email FROM users WHERE id=?"""
        sql_data = self.query(sql_query, (userid,))[0]
        if sql_data[1] == "" or sql_data[1] is None:
            pic = DEFAULT_CHAT_IMAGE
        else:
            pic = sql_data[1]
        is_online_query = """SELECT timestopped FROM tokens WHERE userid=? AND timestopped IS NULL LIMIT 1"""
        is_online = self.query(is_online_query, (userid,))
        if len(is_online) > 0:
            last_on = is_online[0][0]
        else:
            last_seen_query = """SELECT timestopped FROM tokens WHERE userid=? ORDER BY timestopped DESC LIMIT 1"""
            last_seen = self.query(last_seen_query, (userid,))
            if len(last_seen) == 0:
                last_on = "Never"
            else:
                last_on = last_seen[0][0]
        return {"username": sql_data[0], "picture": pic, "email": sql_data[2], "Last-Seen" : last_on}

    def get_all_user_data(self, userid: str) -> dict:
        pass

    def token_to_id(self, token: str) -> int:
        """
        Gets the user id from of the token
        :param token: token
        :return: user id that matches the token
        """
        sql_query_if_usable = """SELECT timestopped FROM tokens WHERE token=?"""
        time_stopped = self.query(sql_query_if_usable, (token,))[0]
        if time_stopped is None:
            return -1
        sql_query = """SELECT userid FROM tokens WHERE token=?"""
        return int(self.query(sql_query, (token,))[0][0])

    def is_token_exists(self, token : str) -> bool:
        """
        Checks if the token exists in the db
        :param token: token
        :return: True if exists, False otherwise
        """
        sql_query = """SELECT * FROM tokens WHERE token=?"""
        return len(self.query(sql_query, (token,))) > 0

    def is_message_exists(self, group_id: str, msg_id: str) -> bool:
        """
        Checks if the message exists in the db
        :param group_id: group id
        :param msg_id: message id
        :return: True if exists, False otherwise
        """
        sql_query = f"""SELECT * FROM chat{group_id} WHERE msgid=?"""
        return len(self.query(sql_query, (msg_id,))) > 0

    def delete_message(self, group_id: str, msg_id: str):
        """
        Deletes a message from the db
        :param group_id: group id
        :param msg_id: message id
        """
        sql_query = f"""UPDATE chat{group_id} SET type="deleted", textcontent="", attachments="[]" WHERE msgid=?"""
        self.query(sql_query, (msg_id,))

    def is_message_editable(self, group_id : str, msg_id : str) -> bool:
        """
        Checks if the message is editable
        :param group_id: the id of the group where the msg is
        :param msg_id: the id of the message
        :return: True if editable, False otherwise
        """
        sql_query = f"""SELECT type FROM chat{group_id} WHERE msgid=?"""
        return self.query(sql_query, (msg_id,))[0][0] != "deleted"


    def is_message_sender(self, group_id: str, msg_id: str, user_id: str) -> bool:
        """
        Checks if the user is the sender of the message
        :param group_id: group id
        :param msg_id: message id
        :param user_id: user id
        :return: True if the user is the sender, False otherwise
        """
        sql_query = f"""SELECT senderid FROM chat{group_id} WHERE msgid=?"""
        return self.query(sql_query, (msg_id,))[0][0] == user_id


    def get_group_data(self, group_id: str) -> dict:
        """
        Gets the group data (name, pfp, type, id , members)
        members is a list of user ids
        :param group_id: group id
        :return: group data
        """
        sql_query = """SELECT name, picture, type , id, groupmembersbyid, metadata FROM chats WHERE id=?"""
        data = self.query(sql_query, (group_id,))[0]
        if data[1] == "" or data[1] is None:
            pic = DEFAULT_CHAT_IMAGE
        else:
            pic = data[1]
        return {"name": data[0], "picture": pic, "type": data[2], "id": data[3], "members": json.loads(data[4]), "metadata" : json.loads(data[5])}


    def fetch_group_ids(self, user_id: str) -> list:
        """
        Gets the group ids of the user (list)
        :param user_id: user id
        :return: list of group ids
        """
        sql_query = """SELECT arrayOfChats FROM users WHERE id=?"""
        return json.loads(self.query(sql_query, (user_id,))[0][0])

    @staticmethod
    def gen_token_string():
        """
        Generates a random string of length 20 comprised of upper chars and digits
        Used for tokens
        :return: random string
        """
        random_string = ""
        for i in range(20):
            random_string += random.choice(string.ascii_uppercase + string.digits)
        return random_string

    def get_new_random_token(self) -> str:
        """
        Gets a new random token that is unique in the db
        Used for tokens
        :return: random token
        """
        does_token_exist_query = """SELECT * FROM tokens WHERE token=?"""
        random_token = LockableSqliteConnection.gen_token_string()
        while len(self.query(does_token_exist_query, (random_token,))) > 0:
            random_token = LockableSqliteConnection.gen_token_string()
        return random_token

    def set_token_offline(self, token: str) -> None:
        pass

    def get_id_from_email_and_password(self, email: str, password: str) -> str:
        """
        Gets the user id from the email and password
        should be a match (should not be used for login check)
        :param email: email
        :param password: password
        :return: user id that matches the email and password
        # """
        password = sha256(password.encode('utf-8')).hexdigest()
        sql_query = """SELECT id FROM users WHERE email=? AND password=?"""
        return self.query(sql_query, (email, password))[0][0]

    def set_and_get_new_token(self, user_id: str, ip_addr : str) -> str:
        """
        Sets a new token for the user and returns it
        :param user_id: user id
        :return: new token
        """
        token = self.get_new_random_token()
        sql_query = """INSERT INTO tokens (token, timeissued, userid, ip) VALUES (?,?,?, ?)"""
        self.query(sql_query, (token, time.time(), user_id, ip_addr))
        return token

    def check_password_email_match(self, email: str, password: str) -> bool:
        """
        Checks if the email and password match for some user
        used for login
        :param email: email
        :param password: password
        :return: True if they match, False otherwise
        """

        password = sha256(password.encode('utf-8')).hexdigest()
        sql_query = """SELECT * FROM users WHERE email=? AND password=?"""
        return len(self.query(sql_query, (email, password))) > 0

    def is_user_enabled(self, email : str, password : str) -> bool:
        """
        checks if user is enabled in the db
        :param email: email
        :param password: password
        :return: true if user is enabled else false
        """
        password = sha256(password.encode('utf-8')).hexdigest()
        sql_query = """SELECT * FROM users WHERE email=? AND password=? AND enabled=1"""
        return len(self.query(sql_query, (email, password))) > 0

    def save_new_user_to_db(self, email: str, password: str, username: str, imageb64: str) -> int:
        """
        Saves a new user to the db (into users table - email, name, arrayofchats, password, picture)
        Returns the user id
        :param email: email
        :param password: password
        :param username: username
        :param imageb64: image in base64 (data url)
        :return: user id
        """
        sql_query = """INSERT INTO users (email, uname, arrayOfChats, password, picture, enabled) VALUES (?,?,?,?,?,0)"""
        return self.query(sql_query, (email, username, json.dumps([]), sha256(password.encode('utf-8')).hexdigest(), imageb64))

    def enable_user(self, uid : int | str) -> int:
        """
        Enables a user in the db (enabled=1)
        :param uid: the id of the user to enable
        :return: the id of the user that was enabled
        """
        sql_query = """UPDATE users SET enabled=1 WHERE id=?"""
        return self.query(sql_query, (uid,))

    def delete_code(self, uid : int | str):
        """
        Deletes the last code (2fa code) for a user
        :param uid: the id of the user to delete the code for
        :return: the id of the user that its code was deleted
        """
        sql_query = """UPDATE users SET lastcode=? WHERE id=?"""
        return self.query(sql_query, (None, uid))

    def is_user_exists(self, uid : int | str) -> bool:
        """
        Checks if a user exists in the db
        :param uid: the id of the user to check
        :return: True if the user exists, False otherwise
        """
        data = self.query("SELECT * FROM users WHERE id=?", (uid,))
        print(data)
        return len(data) > 0

    def get_last_code(self, uid : int | str) -> str | int:
        """
        Gets the last code (2fa code) for a user
        :param uid: the user to get the code for
        :return: the last code (2fa code) for the user
        """
        sql_query = """SELECT lastcode FROM users WHERE id=?"""
        return self.query(sql_query, (uid,))[0][0]

    def is_email_exists(self, email : str) -> bool:
        """
        Checks if an email exists in the db
        :param email: the email to check
        :return: True if the email exists, False otherwise
        """
        sql_query = """SELECT * FROM users WHERE email=?"""
        return len(self.query(sql_query, (email,))) > 0

    def save_last_code(self, id : str, code : str):
        """
        Saves the last code (2fa code) for a user
        :param id: the id of the user to save the code for
        :param code: the code to save
        :return: None
        """
        sql_query = """UPDATE users SET lastcode=? WHERE id=?"""
        self.query(sql_query, (code, id))

    def set_new_2fa_token(self, id : str) -> str:
        """
        generates and sets a new 2fa token for a user
        :param id: the id of the user to set the token for
        :return: the new token
        """
        token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        sql_query = """UPDATE users SET lastissued2fatoken=? WHERE id=?"""
        self.query(sql_query, (token, id))
        return token

    def get_latest_2fa_token(self, id : str) -> str:
        """
        Gets the latest 2fa token for a user
        :param id: the id of the user to get the token for
        :return: the latest 2fa token for the user
        """
        latest_tok = self.query("""SELECT lastissued2fatoken FROM users WHERE id=?""", (id,))[0][0]
        print("latest tok is")
        print(latest_tok)
        return latest_tok

    def get_email_of_user(self, id : str) -> str:
        """
        Gets the email of a user
        :param id: the id of the user to get the email for
        :return: the email of the user
        """
        sql_query = """SELECT email FROM users WHERE id=?"""
        return self.query(sql_query, (id,))[0][0]
    def get_latest_message(self, group_id : str) -> dict | None:
        """
        Gets the latest message in a group
        :param group_id: group id
        :return: latest message in the group (dict(msgid, senderid, textcontent, timesent, type, attachments))
        """
        last_twenty_messages = self.fetch_msgs(group_id, 0 ,0)
        if len(last_twenty_messages) == 0:
            return None
        return last_twenty_messages[0]

    def get_token_type(self, token : str) -> str:
        """
        Gets the token type for a token
        :param token: the token to get its type
        :return: the tokens type
        """
        sql_query = f"""SELECT tokentype FROM tokens WHERE token=?"""
        data = self.query(sql_query, (token,))
        print(data)
        return data[0][0]

    def get_all_users_on_ids(self) -> list:
        """
        Gets all ids of users on
        :return: list of tuples (id, username)
        """
        sql_query = f"""SELECT DISTINCT users.id, users.uname FROM tokens JOIN users ON tokens.userid = users.id WHERE tokens.timestopped IS NULL"""
        return self.query(sql_query)

    def set_token_unusable(self, token : str) -> None:
        """
        Sets a token unusable (timestopped not 0 or null)
        :param token: token
        :return: None
        """

        sql_query = f"""UPDATE tokens SET timestopped=? WHERE token=?"""
        self.query(sql_query, (time.time(), token))


    def __init__(self, dburi: str):
        """
        Initializes the database connection
        :param dburi: the 'link' to the database file
        """
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(dburi, uri=True, check_same_thread=False)
        print("self connection autocommit is")
        print(self.connection.autocommit)
        print("printed")
        self.connection.execute('pragma journal_mode=wal')
        self.connection.autocommit = False
        #self.connection.execute('pragma journal_mode=DELETE')
        #self.cursor = None
        self.commitCounter = 0
        self.commitLimit = 100

    def __enter__(self):
        """
        locks the database connection
        :return: itself (for context manager)
        """
        self.lock.acquire()
        return self

    def __exit__(self, _, value, traceback):
        """
        unlocks the database connection
        :param _: the exception type
        :param value: the exception value
        :param traceback: the exception traceback
        :return: None
        """
        self.lock.release()

    def query(self, query_string, values=tuple()) -> int | list | None:
        """
        function that executes a sql query and returns an appropriate value
        :param query_string: string that represents the full sql query
        :param values: a tuple that represents the parameters for the query
        :return: in case of select, returns the selected data, in other cases returns 0 for success and None for failure
        """

        #print(f"query is {query_string}")
        with self:
            #self.cursor.execute(query_string, values)
            conn = self.connection.execute(query_string, values)
            match query_string[0:1]:
                case "S":
                    #rows = self.cursor.fetchall()
                    rows = conn.fetchall()
                    return rows
                case "I":
                    #self.connection.commit()
                    if self.commitCounter >= self.commitLimit:
                        self.connection.commit()
                        self.commitCounter = 0
                    self.commitCounter += 1
                    return conn.lastrowid
                    #return self.cursor.lastrowid
                case _:
                    #self.connection.commit()
                    if self.commitCounter >= self.commitLimit:
                        self.connection.commit()
                        self.commitCounter = 0
                    self.commitCounter += 1

    def update_msg_read_receipt(self, user_id : int, group_id : str, msg_id : str, time_read : str) -> None:
        """
        Updates the msg read receipt in the db
        :param user_id: user id
        :param group_id: group id
        :param msg_id: message id
        :param time_read: time read
        :return: None
        """
        sql_query = f"""UPDATE chat{group_id} SET user{str(user_id)}=? WHERE msgid=?"""
        self.query(sql_query, (time_read, msg_id))


    def set_server_token(self, token : str) -> None:
        """
        Sets a token as a server token
        :param token: the token to set as a servertype
        :return: None
        """
        sql_query = """UPDATE tokens SET tokentype="server" WHERE id=?"""
        self.query(sql_query, (token,))

    def does_message_exist(self, group_id : str, message_id : str ) -> bool:
        """
        Checks if a message exists in a group
        :param group_id: group id
        :param message_id: message id
        :return: True if it exists, False otherwise
        """

        sql_query = f"""SELECT * FROM chat{group_id} WHERE msgid=?"""
        return len(self.query(sql_query, (message_id,))) > 0

    def edit_message(self, group_id : str, message_id : str, new_text : str) -> int:
        """
        Edits a message's content
        :param group_id: the group id where the message is
        :param message_id: the id of the message
        :param new_text: the new message content to set
        :return: the id of the message that was edited
        """
        sql_query = f"""UPDATE chat{group_id} SET textcontent=?, lastedited=? WHERE msgid=?"""
        return self.query(sql_query, (new_text, time.time(), message_id))

    def add_user_to_group(self, group_id, user_id):
        """
        Adds a user to a group (changes in chats db and users db) and prevents thread switching during this function ( as we need to make sure the 2 queries are not interrupted)
        :param group_id: the group id to add the user to
        :param user_id: the user id to be added
        :return: None
        """
        current_sys_interval = sys.getswitchinterval()
        print(current_sys_interval)
        sys.setswitchinterval(100000000) #TO PREVENT THREAD SWITCHING - SINCE WE NEED TO EXECUTE 2 COMMANDS HERE AND WE HAVE TO MAKE SURE THAT THEY ARE NOT INTERRUPTED
        sql_query = f"""alter table chat{group_id} add column user{user_id} int default 0"""
        self.query(sql_query, tuple())
        sql_query = f"""SELECT groupmembersbyid FROM chats WHERE id=?"""
        members = self.query(sql_query, (group_id,))[0][0]
        members = json.loads(members)
        members.append(user_id)
        sql_query = f"""UPDATE chats SET groupmembersbyid=? WHERE id=?"""
        self.query(sql_query, (json.dumps(members), group_id))
        sql_query = f"""SELECT arrayOfChats FROM users WHERE id=?"""
        chats = self.query(sql_query, (user_id,))[0][0]
        chats = json.loads(chats)
        chats.append(group_id)
        sql_query = f"""UPDATE users SET arrayOfChats=? WHERE id=?"""
        self.query(sql_query, (json.dumps(chats), user_id))
        sys.setswitchinterval(current_sys_interval)

