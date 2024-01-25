import base64
import json
import socket
import time
import traceback

import uuid

from pycallgraph2 import PyCallGraph
from pycallgraph2.output import GraphvizOutput

import dataBaseClass
import messageProt
import messages
import logging
import threading

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024


class BroadCaster:
    def __init__(self):
        self.data_lock = threading.Lock()
        self.users_dict = dict()
    def new_event(self, event_type: str, event_data : dict, sql_lockable : dataBaseClass.LockableSqliteConnection):
        """
        function to be alerted on new event
        :param event_type: string of event type
        :param event_data: dict of event data
        :param sql_lockable: sql locckable object to the db
        :return: none
        """
        ##print(event_data)
        match event_type:
            case "msg":
                group_id = event_data["create-args"]["group_id"]
                new_id = event_data["new_id"]
                new_message = {"type" : "server-update", "update-data" : {"type" : "new-msg", "group_id" : group_id, "msg-data" :  sql_lockable.fetch_msgs(group_id, new_id, new_id)}}
                target_ids = sql_lockable.get_group_participants(group_id)
                ##print(target_ids)
                for uid in target_ids:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            try:
                                newThread = threading.Thread(target=messageProt.messageProt.send_msg, args=(sock, json.dumps(new_message)))
                                newThread.start()
                                #messageProt.messageProt.send_msg(sock, json.dumps(new_message))
                            except Exception as e:
                                pass
                                #print(f"error sending msg to {uid}")
            case "group":
                group_id = event_data["new_id"]
                group_data = sql_lockable.get_group_data(group_id)
                group_data["latest_msg"] = sql_lockable.get_latest_message(group_id)
                new_message = { "type" : "server-update", "update-data" : {"type" : "new-group", "group-data" : group_data}}
                for uid in event_data["create-args"]["group_participants"]:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            messageProt.messageProt.send_msg(sock, json.dumps(new_message))
            case "msg-read_receipt":
                msg_id = event_data["update-args"]["msg_id"]
                group_id = event_data["update-args"]["group_id"]
                target_ids = sql_lockable.get_group_participants(group_id)
                new_message = { "type" : "server-update", "update-data" : {"type" : "msg-read_receipt", "group_id" : group_id, "msg_id" : msg_id, "user_read" : sql_lockable.token_to_id(event_data["update-args"]["token"]), "time_read" : event_data["update-args"]["time_read"]}}
                for uid in target_ids:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            messageProt.messageProt.send_msg(sock, json.dumps(new_message))
        #log.warning(f"event type is {event_type}")

    def broadcast_message(self, message_dict: dict, targets: list):
        pass

    def add_to_available_list(self, user_id: str, token:str ,sock: socket.socket):
        """
        add a user to the available list with its token
        :param user_id: userid
        :param token:  token
        :param sock: socket of user
        :return: none
        """
        user_id = str(user_id)
        with self.data_lock:
            if user_id not in self.users_dict:
                self.users_dict[user_id] = [(sock, token)]
            else:
                self.users_dict[user_id].append((sock, token))

    def remove_from_available_list(self, sock: socket.socket) -> str:
        """
        remove a user from the available list and returns its token
        :param sock: socket of user
        :return: token of user
        """
        with self.data_lock:
            for uid, sock_list in self.users_dict.items():
                if sock in list((lambda x: x[0])(x) for x in sock_list):
                    token = list(filter(lambda x: x[0] == sock, sock_list))[0][1]
                    ##print(token)
                    if len(sock_list) > 1:
                        sock_list.pop(list((lambda tup: tup[0])(tup) for tup in sock_list).index(sock))
                    else:
                        del self.users_dict[uid]
                    return token




def is_fetch_message(msg_dict: dict) -> bool:
    """
    check if a message is a fetch message
    :param msg_dict: dict of message
    :return: True if fetch message else false
    """
    return msg_dict["type"] == "fetch"


def is_create_message(msg_dict: dict) -> bool:
    """
    check if a message is a create message
    :param msg_dict: dict of message
    :return: True if create message else false
    """
    return msg_dict["type"] == "create"
    pass

def is_login_message(msg_dict: dict) -> bool:
    """
    check if a message is a login message
    :param msg_dict: dict of message
    :return: True if login message else false
    """
    return msg_dict["type"] == "login"

def decode_string(string: str) -> dict:
    """
    decode a string to dict
    :param string: string to decode
    :return: dict of decoded string
    """
    return json.loads(string)


def encode_data(data_dict: dict) -> str:
    """
    encode a dict to string
    :param data_dict: dict to encode
    :return: string of encoded dict
    """
    return json.dumps(data_dict)


def return_fetch_success(success_data) -> dict:
    """
    return a fetch success message
    :param success_data: data to return
    :return: dict of success message
    """
    return {"success": "1", "fetch-data": success_data}

def return_empty_success() -> dict:
    """
    return an empty success message
    :return: dict of success message without data
    """
    return {"success": "1"}

def return_create_data(success_data) -> dict:
    """
    return a create success message with the success data
    :param success_data:
    :return: dict of success message
    """
    return {"success": "1", "create-data": success_data}


def return_error_message(error_data) -> dict:
    """
    return an error message with data
    :param error_data: data to return
    :return: dict of error message with data
    """
    return {"success": "0", "error-data": error_data}


def do_fetch(fetch_args: dict, sql_lockable: dataBaseClass.LockableSqliteConnection) -> dict | list[dict]:
    """
    do a fetch and returns its data
    :param fetch_args: dict of fetch args
    :param sql_lockable: sql connection
    :return: dict of fetch data
    """
    if "type" not in fetch_args:
        raise ValueError("invalid fetch args")
    fetch_type = fetch_args["type"]
    match fetch_type:
        case "file":
            if "file_name" not in fetch_args:
                if "file_hash" not in fetch_args:
                    raise ValueError("invalid fetch args")
                fetch_args["file_name"] = fetch_args["file_hash"]
            file_name = fetch_args["file_name"]
            #log.warning("starting to read")
            with open('files/' + file_name, 'rb') as file:
                file_data = file.read()
            file_data = 'data:application/octet-stream;base64,' + base64.b64encode(file_data).decode('utf-8')
            #log.warning("finished to read")
            return {"file_data" : file_data}
        case "users":
            user_ids_tuples = sql_lockable.get_all_users_on_ids()
            ###print(user_ids_tuples)
            user_ids = dict()
            for user_id, user_name in user_ids_tuples:
                user_ids[user_id] = user_name
            ###print(user_ids)
            return user_ids
        case "user":
            if "target_id" not in fetch_args:
                raise ValueError("invalid fetch args")
            if "token" in fetch_args:
                if sql_lockable.token_to_id(fetch_args["token"]) == fetch_args["target_id"]:
                    return sql_lockable.get_all_user_data(fetch_args["target_id"])
                else:
                    return sql_lockable.get_safe_user_data(fetch_args["target_id"])
            else:
                return sql_lockable.get_safe_user_data(fetch_args["target_id"])
        case "groups":
            if "token" not in fetch_args:
                raise ValueError("invalid fetch args")
            ##print(fetch_args["token"])
            ##print(sql_lockable.token_to_id(fetch_args["token"]))
            group_ids = sql_lockable.fetch_group_ids(sql_lockable.token_to_id(fetch_args["token"]))
            groups_data = list()
            for group_id in group_ids:
                group_data = sql_lockable.get_group_data(group_id)
                group_data["latest_msg"] = sql_lockable.get_latest_message(group_id)
                groups_data.append(group_data)
            return groups_data
        case "msgs":
            if "token" not in fetch_args or "lower_bound" not in fetch_args or "upper_bound" not in fetch_args or "target_group" not in fetch_args:
                raise ValueError("invalid fetch args")
            if sql_lockable.is_group_exists(fetch_args["target_group"]) == False:
                raise ValueError("group doesnt not exist")
            user_id = sql_lockable.token_to_id(fetch_args["token"])
            if str(user_id) not in sql_lockable.get_group_participants(fetch_args["target_group"]):
                #log.warning(sql_lockable.get_group_participants(fetch_args["target_group"]))
                raise messages.AuthError("user not in group")
            return sql_lockable.fetch_msgs(fetch_args["target_group"], fetch_args["lower_bound"], fetch_args["upper_bound"])




def do_create(create_args: dict, sql_lockable: dataBaseClass.LockableSqliteConnection) -> str:
    """
    try to create the object and return its new id
    :param create_args: dict of create args
    :param sql_lockable: sql connection
    :return: new id of the object
    """
    if "type" not in create_args:
        raise ValueError("invalid create args")
    create_type = create_args["type"]
    ###print(f" create type is {create_type}, and create args are {create_args}")
    match create_type:
        case "file":
            if "file_b64" not in create_args:
                raise ValueError("invalid create args")
            if "file_name" not in create_args:
                file_name_randomly_created = uuid.uuid4().hex
            else:
                ##print(create_args["file_name"])
                file_name_randomly_created = create_args["file_name"]
            with open("./files/" + file_name_randomly_created, "ab") as f:
                f.write(base64.b64decode(create_args["file_b64"]))
            return file_name_randomly_created
        case "user":
            if "email" not in create_args and "password" not in create_args and "username" not in create_args:
                raise ValueError("invalid create args")
            if "picture" not in create_args:
                create_args["picture"] = None
            return sql_lockable.save_new_user_to_db(create_args["email"], create_args["password"], create_args["username"], create_args["picture"])
        case "group":
            ##print("in here")
            if "group_type" not in create_args or "token" not in create_args:
                raise ValueError("invalid create args")
            if create_args["group_type"] == "1":
                if "group_participants" not in create_args or "group_name" not in create_args:
                    raise ValueError("invalid create args")
                if "group_picture" not in create_args:
                    create_args["group_picture"] = None
                create_args["group_participants"].append(str(sql_lockable.token_to_id(create_args["token"])))
                ##print("in here")
                new_chat_id = sql_lockable.make_new_chat(create_args["group_name"], create_args["group_picture"], create_args["group_type"] ,create_args["group_participants"])
                for user_id in create_args["group_participants"]:
                    sql_lockable.update_user_chats(user_id, new_chat_id)
                ##print(new_chat_id)
                return new_chat_id
        case "msg":
            if "group_id" not in create_args or "msg_content" not in create_args or "token" not in create_args:
                raise ValueError("invalid create args")
            user_id = sql_lockable.token_to_id(create_args["token"])
            if str(user_id) not in sql_lockable.get_group_participants(create_args["group_id"]):
                raise messages.AuthError("user not in group")
            if "attachments" not in create_args:
                create_args["attachments"] = None
            if "msg_type" not in create_args:
                create_args["msg_type"] = "text"
            if "time_sent" not in create_args:
                create_args["time_sent"] = time.time()
            return sql_lockable.save_new_msg(create_args["group_id"],user_id, create_args["msg_content"], create_args["time_sent"], create_args["msg_type"], create_args["attachments"])



def do_login(login_args: dict, sql_lockable: dataBaseClass.LockableSqliteConnection) -> str:
    """
    try to login and return the new token
    :param login_args: dict of login args
    :param sql_lockable: sql connection
    :return: new token of the user
    """
    if "email" not in login_args and "password" not in login_args:
        raise ValueError("invalid login args")
    if sql_lockable.check_password_email_match(login_args["email"], login_args["password"]):
        return sql_lockable.set_and_get_new_token(sql_lockable.get_id_from_email_and_password(login_args["email"], login_args["password"]))
    else:
        raise messages.AuthError("wrong email or password")

def get_create_type(create_args: dict) -> str:
    """
    get the type of the create args
    :param create_args: dict of create args
    :return: type of the create args
    """
    return create_args["type"]


def is_update_message(message_dict : dict) -> bool:
    """
    check if the message is an update message
    :param message_dict: dict of the message
    :return: true if the message is an update message else false
    """
    return message_dict["type"] == "update"


def do_update(update_args: dict, sql_lockable : dataBaseClass.LockableSqliteConnection):
    """
    update the neccessary data in the database
    and return the id of the updated object

    :param update_args: dict of the update args
    :param sql_lockable: sql connection
    :return: the id of the updated object
    """

    if "type" not in update_args:
        raise ValueError("invalid update args")
    update_type = update_args["type"]
    match update_type:
        case "msg-read_receipt":
            if "time_read" not in update_args or "msg_id" not in update_args or "token" not in update_args or "group_id" not in update_args:
                raise ValueError("invalid update args")
            user_id = sql_lockable.token_to_id(update_args["token"])
            if str(user_id) not in sql_lockable.get_group_participants(update_args["group_id"]):
                raise messages.AuthError("user not in group")
            if not sql_lockable.does_message_exist(update_args["group_id"], update_args["msg_id"]):
                raise ValueError("message does not exist")
            sql_lockable.update_msg_read_receipt(user_id, update_args["group_id"],update_args["msg_id"], update_args["time_read"])
            return update_args["msg_id"]
    pass


def get_update_type(update_args : dict) -> str:
    """
    get the type of the update args
    :param update_args: dict of the update args
    :return: type of the update args
    """
    return update_args["type"]


def is_fetch_chunks(message_dict) -> bool:
    """
    check if the message is a fetch chunks message
    :param message_dict:
    :return: True if fetch chunks message else False
    """
    return message_dict["type"] == "fetch-chunks"


def return_chunk_fetch_sucess(fetch_data) -> dict:
    """
    return a fetch chunks success message with data
    :param fetch_data: data to return
    :return: fetch chunks success message with data
    """
    return {"type" : "fetch-chunks-server", "chunks" : fetch_data}


def do_fetch_chunk(fetch_args : dict, sql_lockable : dataBaseClass.LockableSqliteConnection) -> dict | list[dict]:
    """
    fetches the chunk and returns it
    :param fetch_args: fetch args
    :param sql_lockable: sql lockable object
    :return: chunk data or list of chunks
    """
    if "type" not in fetch_args:
        raise ValueError("invalid fetch args")
    fetch_type = fetch_args["type"]
    match fetch_type:
        case "file":
            if "file_hash" not in fetch_args:
                raise ValueError("invalid fetch args")
            if do_fetch_chunk.file_pointer is None:
                do_fetch_chunk.file_pointer = open(f"files/{fetch_args['file_hash']}", "rb")
            file_data = do_fetch_chunk.file_pointer.read(CHUNK_SIZE)
            ###print({"type" : "file", "is_end" : len(file_data) == 0, "file_data" : base64.b64encode(file_data).decode('utf8')})
            if len(file_data) == 0:
                do_fetch_chunk.file_pointer.close()
                do_fetch_chunk.file_pointer = None
            return [{"file_hash" : fetch_args["file_hash"],"type" : "file", "is_end" : len(file_data)== 0, "file_data" : base64.b64encode(file_data).decode('utf8')}]
do_fetch_chunk.file_pointer = None


def do_signout(sql_lockable : dataBaseClass.LockableSqliteConnection, token :str) -> None:
    """
    signout the user (set token to unusable)
    :param sql_lockable: sql lockable object
    :param token: token of the user
    :return: None
    """
    sql_lockable.set_token_unusable(token)

def _handler_thread_function(broadcaster_instance: BroadCaster, sock: socket.socket,
                            sql_lockable: dataBaseClass.LockableSqliteConnection):
    """
    the main thread function. the thread lives here and handles the messages
    :param broadcaster_instance: broadcaster object instance
    :param sock: socket to recv or send to and from
    :param sql_lockable: sql lockable object
    :return: None
    """
    latest_token = None
    #log.warning("in handler thread function")
    try:
        while True:
            print("starting to read")
            (new_message_string, seq) = messageProt.messageProt.recv_msg(sock)
            print("finished to read")
            print(new_message_string)
            message_dict = decode_string(new_message_string)
            try:
                if is_fetch_message(message_dict):
                    if "fetch-args" not in message_dict:
                        raise ValueError("invalid fetch args")
                    fetch_data = do_fetch(message_dict["fetch-args"], sql_lockable)
                    message_string = encode_data(return_fetch_success(fetch_data))
                    messageProt.messageProt.send_msg(sock, message_string, seq)
                elif is_create_message(message_dict):
                    if "create-args" not in message_dict:
                        raise ValueError("invalid create args")
                    new_id = do_create(message_dict["create-args"], sql_lockable)
                    message_string = encode_data(return_create_data(new_id))
                    messageProt.messageProt.send_msg(sock, message_string, seq)
                    broadcaster_instance.new_event(get_create_type(message_dict["create-args"]), {"new_id" : new_id, "create-args" : message_dict["create-args"]}, sql_lockable)
                elif is_login_message(message_dict):
                    if "login-args" not in message_dict:
                        raise ValueError("invalid login args")
                    latest_token = do_login(message_dict["login-args"], sql_lockable)
                    latest_id = sql_lockable.token_to_id(latest_token)
                    messageProt.messageProt.send_msg(sock, encode_data(return_fetch_success({"token" : latest_token, "id" : latest_id})), seq)
                    broadcaster_instance.add_to_available_list(sql_lockable.token_to_id(latest_token), latest_token, sock)
                elif is_update_message(message_dict): #get updated_id from do_update func, and pass it to broadcaster
                    #log.warning("##printing update args")
                    #log.warning(message_dict)
                    if "update-args" not in message_dict:
                        raise ValueError("invalid update args")
                    #log.warning("going to do update now")
                    updated_id = do_update(message_dict["update-args"], sql_lockable)
                    message_string = encode_data(return_empty_success())
                    messageProt.messageProt.send_msg(sock, message_string, seq)
                    broadcaster_instance.new_event(get_update_type(message_dict["update-args"]), {"updated_id" : updated_id, "update-args" : message_dict["update-args"]}, sql_lockable)
                elif is_fetch_chunks(message_dict):
                    fetch_data = do_fetch_chunk(message_dict["fetch-args"], sql_lockable)
                    #while(anytfetch_data["is_end"] is False):
                    while(all(list(map(lambda x: x["is_end"], fetch_data))) is False):
                        message_string = encode_data(return_chunk_fetch_sucess(fetch_data))
                        messageProt.messageProt.send_msg(sock, message_string, 0)
                        fetch_data = do_fetch_chunk(message_dict["fetch-args"], sql_lockable)
                else:
                    raise TypeError("invalid message type")
            except messages.AuthError as e:
                #log.warning(e)
                message_string = encode_data(return_error_message(str(e)))
                messageProt.messageProt.send_msg(sock, message_string, seq)
                continue
                # continue #no need to exit loop here, as it could just mean that the message had incorrect data,
                # which is ok
            except TypeError as e:
                #log.warning("type error")
                #log.warning(e)
                #log.warning(traceback.format_exc())
                message_string = encode_data(return_error_message(str(e)))
                messageProt.messageProt.send_msg(sock, message_string, seq)
                continue
            except ValueError as e:
                #log.warning("value error")
                #log.warning(e)
                message_string = encode_data(return_error_message(str(e)))
                ##print(type(message_string))
                messageProt.messageProt.send_msg(sock, message_string, seq)
            finally:
                print("finished all the processing")
    except TypeError:
        exit()
        pass
    except Exception:
        pass
        #log.warning(traceback.format_exc())
    finally:
        token = broadcaster_instance.remove_from_available_list(sock)
        do_signout(sql_lockable,token)

def handler_thread_function(broadcaster_instance: BroadCaster, sock: socket.socket,
                            sql_lockable: dataBaseClass.LockableSqliteConnection):
    _handler_thread_function(broadcaster_instance, sock,
                        sql_lockable)