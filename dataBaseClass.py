import json
import logging
import sqlite3
import string
import time
import threading
import random
import base64

from sqlite3 import Error
from hashlib import sha256
from default_image import DEFAULT_CHAT_IMAGE

TOKEN_LENGTH = 20

log = logging.getLogger(__name__)


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

    def save_new_msg(self, group_id: str, sender_id: str, text_content: str, time_sent: str, msg_type: str,
                     attachments: list) -> str:
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

    def make_new_chat(self, group_name: str, group_picture: str, group_type: str, group_members: list[str]) -> str:
        """
        Creates a new chat in db (new table and new row)
        :param group_name: group name
        :param group_picture: group picture
        :param group_type: group type
        :param group_members: group members
        :return: new chat id
        """
        create_row_query = """INSERT INTO chats (name, picture, type, groupmembersbyid) VALUES (?,?,?,?)"""
        new_id = self.query(create_row_query, (group_name, group_picture, group_type, json.dumps(group_members)))
        new_table_command = f"""CREATE TABLE IF NOT EXISTS chat{new_id} (msgid integer PRIMARY KEY, senderid integer, textcontent text, timesent text, type text, attachments text, {', '.join(list(map(lambda user_id: "user" + str(user_id) + " integer DEFAULT 0", group_members)))})"""
        with self:
            self.cursor.execute(new_table_command)
        return new_id

    def is_group_exists(self, group_id : str) -> bool:
        """
        Checks if a group exists in the db
        :param group_id: group id
        :return: True if exists, False otherwise
        """
        sql_query = """SELECT * FROM chats WHERE id=?"""
        return len(self.query(sql_query, (group_id,))) > 0

    def get_group_participants(self, group_id: str) -> list:
        """
        Gets the group participants
        :param group_id: group id
        :return: list of participants by id
        """
        sql_query = """SELECT groupmembersbyid FROM  chats WHERE id=?"""
        return json.loads(self.query(sql_query, (group_id,))[0][0])

    def fetch_msgs(self, group_id: str, lower_bound: str | int, upper_bound: str | int) -> list[dict]:
        """
        Fetches messages from the db
        :param group_id: group id
        :param lower_bound: lower bound
        :param upper_bound: upper bound
        :return: list of messages in between the bounds
        """
        if str(lower_bound) == "0" and str(upper_bound) == "0":
            sql_query = f"""SELECT * FROM chat{group_id} ORDER BY msgid DESC LIMIT 20"""
            sql_data = self.query(sql_query, tuple())
        else:
            sql_query = f"""SELECT * FROM chat{group_id} WHERE msgid BETWEEN ? AND ? ORDER BY msgid DESC"""
            sql_data = self.query(sql_query, (lower_bound, upper_bound,))
        return_list = list()
        group_participants = self.get_group_participants(group_id)
        for row in sql_data:
            basic_dict = {"msgid": row[0], "senderid": row[1], "textcontent": row[2], "timesent": row[3],
                          "type": row[4], "attachments": json.loads(row[5]), "read_receipts" : dict()}
            for participant in group_participants:
                basic_dict["read_receipts"][participant] = row[group_participants.index(participant) + 6]
            return_list.append(basic_dict)
        return return_list

    def get_safe_user_data(self, userid: str) -> dict:
        """
        Gets the safe user data from the db
        :param userid: user id
        :return: user data (name, pfp, email, last_seen? to be implemented)
        """
        sql_query = """SELECT uname, picture, email FROM users WHERE id=?"""
        sql_data = self.query(sql_query, (userid,))[0]
        if sql_data[1] == "" or sql_data[1] is None:
            pic = DEFAULT_CHAT_IMAGE
        else:
            pic = sql_data[1]
        return {"username": sql_data[0], "picture": pic, "email": sql_data[2]}

    def get_all_user_data(self, userid: str) -> dict:
        pass

    def token_to_id(self, token: str) -> str:
        """
        Gets the user id from of the token
        :param token: token
        :return: user id that matches the token
        """
        sql_query_if_usable = """SELECT timestopped FROM tokens WHERE token=?"""
        time_stopped = self.query(sql_query_if_usable, (token,))[0]
        if time_stopped is None:
            return "-1"
        sql_query = """SELECT userid FROM tokens WHERE token=?"""
        return self.query(sql_query, (token,))[0][0]

    def get_group_data(self, group_id: str) -> dict:
        """
        Gets the group data (name, pfp, type, id , members)
        members is a list of user ids
        :param group_id: group id
        :return: group data
        """
        sql_query = """SELECT name, picture, type , id, groupmembersbyid FROM chats WHERE id=?"""
        data = self.query(sql_query, (group_id,))[0]
        if data[1] == "" or data[1] is None:
            pic = DEFAULT_CHAT_IMAGE
        else:
            pic = data[1]
        return {"name": data[0], "picture": "", "type": data[2], "id": data[3], "members": json.loads(data[4])}

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

    def set_and_get_new_token(self, user_id: str) -> str:
        """
        Sets a new token for the user and returns it
        :param user_id: user id
        :return: new token
        """
        token = self.get_new_random_token()
        sql_query = """INSERT INTO tokens (token, timeissued, userid) VALUES (?,?,?)"""
        self.query(sql_query, (token, time.time(), user_id))
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

    def save_new_user_to_db(self, email: str, password: str, username: str, imageb64: str) -> str:
        """
        Saves a new user to the db (into users table - email, name, arrayofchats, password, picture)
        Returns the user id
        :param email: email
        :param password: password
        :param username: username
        :param imageb64: image in base64 (data url)
        :return: user id
        """
        sql_query = """INSERT INTO users (email, uname, arrayOfChats, password, picture) VALUES (?,?,?,?,?)"""
        return self.query(sql_query, (email, username, json.dumps([]), sha256(password.encode('utf-8')).hexdigest(), imageb64))

    def get_latest_message(self, group_id : str) -> dict | None:
        """
        Gets the latest message in a group
        :param group_id: group id
        :return: latest message in the group (dict(msgid, senderid, textcontent, timesent, type, attachments))
        """
        sql_query = f"""SELECT * FROM chat{group_id} ORDER BY msgid DESC LIMIT 1"""
        sql_data = self.query(sql_query, tuple())
        if len(sql_data) == 0:
            return None
        row = sql_data[0]
        group_participants = self.get_group_participants(group_id)
        basic_dict = {"msgid": row[0], "senderid": row[1], "textcontent": row[2], "timesent": row[3],
                      "type": row[4], "attachments": row[5]}
        for participant in group_participants:
            basic_dict[participant] = row[group_participants.index(participant) + 6]
        return basic_dict

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
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(dburi, uri=True, check_same_thread=False)
        self.cursor = None

    def __enter__(self):
        self.lock.acquire()
        # print("acquired")
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, _, value, traceback):
        self.connection.commit()
        if self.cursor is not None:
            self.cursor.close()
            self.cursor = None
        self.lock.release()
        # print("released")

    def query(self, query_string, values=tuple()):
        """
        function that executes a sql query and returns an appropriate value
        :param query_string: string that represents the full sql query
        :param values: a tuple that represents the parameters for the query
        :return: in case of select, returns the selected data, in other cases returns 0 for success and None for failure
        """

        #print(f"query is {query_string}")
        with self:
            self.cursor.execute(query_string, values)
            match query_string[0:1]:
                case "S":
                    rows = self.cursor.fetchall()
                    return rows
                case "I":
                    self.connection.commit()
                    return self.cursor.lastrowid
                case _:
                    self.connection.commit()

    def update_msg_read_receipt(self, user_id : str, group_id : str, msg_id : str, time_read : str) -> None:
        """
        Updates the msg read receipt in the db
        :param user_id: user id
        :param group_id: group id
        :param msg_id: message id
        :param time_read: time read
        :return: None
        """
        sql_query = f"""UPDATE chat{group_id} SET user{user_id}=? WHERE msgid=?"""
        self.query(sql_query, (time_read, msg_id))



    def does_message_exist(self, group_id : str, message_id : str ) -> bool:
        """
        Checks if a message exists in a group
        :param group_id: group id
        :param message_id: message id
        :return: True if it exists, False otherwise
        """

        sql_query = f"""SELECT * FROM chat{group_id} WHERE msgid=?"""
        return len(self.query(sql_query, (message_id,))) > 0

