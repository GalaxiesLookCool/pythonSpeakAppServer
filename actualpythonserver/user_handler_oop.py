import ast
import base64
import json
import os
import random
import socket
import string
import time
import traceback
import uuid
from io import BytesIO
from stat import S_IREAD, S_IRGRP, S_IROTH
from pathlib import Path
import shutil



import dataBaseClass
import default_image
import messageProt
import messages
from email2fa import send_email_2fa
from user_handler import BroadCaster

from PIL import Image
import logging

CHUNK_SIZE = 1024


def is_file_in_use(file_path):
    """
    checks if file has a file handle open to it
    :param file_path: the file to check
    :return: True if file is in use, false otherwise
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError

    try:
        path.rename(path)
    except PermissionError:
        return True
    else:
        return False

class user_handler_object:
    def do_fetch(self, fetch_args : dict):
        """
        function that handles the fetch requests
        :param fetch_args: the arguements for the fetch request
        :return: the fetched data
        """
        if "type" not in fetch_args:
            raise ValueError("missing type in fetch args")
        fetch_type = fetch_args["type"]
        match fetch_type:
            case "file":
                if "file_name" not in fetch_args:
                    if "file_hash" not in fetch_args:
                        raise ValueError("invalid fetch args - missing file_name or file_hash")
                    fetch_args["file_name"] = fetch_args["file_hash"]
                file_name = fetch_args["file_name"]
                with open('files/' + file_name, 'rb') as file:
                    file_data = file.read()
                file_data = 'data:application/octet-stream;base64,' + base64.b64encode(file_data).decode('utf-8')
                return {"file_data" : file_data}
            case "users":
                user_ids_tuples = self.sql_lockable.get_all_users_on_ids()
                user_ids = dict()
                for user_id, user_name in user_ids_tuples:
                    user_ids[user_id] = user_name
                return user_ids
            case "users_filtered_email":
                if "email_filter" not in fetch_args:
                    raise ValueError("invalid fetch args - missing email_filter")
                email_filter = fetch_args["email_filter"]
                filtered_ids_and_emails = self.sql_lockable.get_user_emails_ids_by_filter(email_filter)
                return filtered_ids_and_emails
            case "user":
                if "target_id" not in fetch_args:
                    raise ValueError("invalid fetch args")
                if "token" in fetch_args:
                    if self.sql_lockable.token_to_id(fetch_args["token"]) == fetch_args["target_id"]:
                        return self.sql_lockable.get_all_user_data(fetch_args["target_id"])
                    else:
                        return self.sql_lockable.get_safe_user_data(fetch_args["target_id"])
                else:
                    return self.sql_lockable.get_safe_user_data(fetch_args["target_id"])
            case "groups":
                if "token" not in fetch_args:
                    raise ValueError("invalid fetch args")
                ##print(fetch_args["token"])
                ##print(sql_lockable.token_to_id(fetch_args["token"]))
                group_ids = self.sql_lockable.fetch_group_ids(self.sql_lockable.token_to_id(fetch_args["token"]))
                if "target_group" in fetch_args:
                    if fetch_args["target_group"] not in group_ids:
                        raise messages.AuthError("user not in group")
                    group_ids = [fetch_args["target_group"]]
                groups_data = list()
                for group_id in group_ids:
                    group_data = self.sql_lockable.get_group_data(group_id)
                    group_data["latest_msg"] = self.sql_lockable.get_latest_message(group_id)
                    #group_data["activecall"] = self.voip_server.get_fetch_data_for_group(group_id)
                    groups_data.append(group_data)
                print("groups data is")
                print(groups_data)
                return groups_data
            case "msgs":
                if "token" not in fetch_args or "lower_bound" not in fetch_args or "upper_bound" not in fetch_args or "target_group" not in fetch_args:
                    raise ValueError("invalid fetch args")
                if self.sql_lockable.is_group_exists(fetch_args["target_group"]) == False:
                    raise ValueError("group doesnt not exist")
                user_id = self.sql_lockable.token_to_id(fetch_args["token"])
                if str(user_id) not in self.sql_lockable.get_group_participants(fetch_args["target_group"]) and int(user_id) not in self.sql_lockable.get_group_participants(fetch_args["target_group"]):
                    #log.warning(sql_lockable.get_group_participants(fetch_args["target_group"]))
                    print("user id is ")
                    print(user_id)
                    print("participants are")
                    print(self.sql_lockable.get_group_participants(fetch_args["target_group"]))
                    print(type(self.sql_lockable.get_group_participants(fetch_args["target_group"])))
                    raise messages.AuthError("user not in group")
                return self.sql_lockable.fetch_msgs(fetch_args["target_group"], fetch_args["lower_bound"], fetch_args["upper_bound"])

    def do_create(self, create_args):
        """
        function that handles the create requests
        :param create_args: the arguements for the create request
        :return: the id of the created object
        """
        if "type" not in create_args:
            raise ValueError("invalid create args")
        create_type = create_args["type"]
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
                if "picture" not in create_args or create_args["picture"] == "" or create_args["picture"] is None:
                    create_args["picture"] = None
                else:
                    pic = create_args["picture"]
                    pic_b64_raw_data = pic.split(";base64,")[1]
                    # print(pic_b64_raw_data)
                    pic_data = Image.open(BytesIO(base64.b64decode(pic_b64_raw_data)))
                    print(pic_data)
                    pic_data = pic_data.resize((200, 200))
                    print(pic_data)
                    buffered = BytesIO()
                    pic_data.save(buffered, format="PNG")
                    print(buffered)
                    img_str = base64.b64encode(buffered.getvalue())
                    print(img_str.decode())
                    # img_str = base64.b64encode(buffered.getvalue())
                    create_args["picture"] = pic.split(";base64,")[0] + ";base64," + img_str.decode()
                    print(create_args["picture"])
                if self.sql_lockable.is_email_exists(create_args["email"]):
                    raise ValueError("Email already being used!")
                id = self.sql_lockable.save_new_user_to_db(create_args["email"], create_args["password"],
                                                           create_args["username"], create_args["picture"])
                code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                twofatoken = self.sql_lockable.set_new_2fa_token(id)
                send_email_2fa(create_args["email"], code)
                self.sql_lockable.save_last_code(id, code)
                return {"new_id": id, "need": "2fa", "email_sent": create_args["email"], "2fa-token": twofatoken}
            case "group":
                ##print("in here")
                if "group_type" not in create_args or "token" not in create_args:
                    raise ValueError("invalid create args")
                if create_args["group_type"] == "1":
                    if "group_participants" not in create_args or "group_name" not in create_args:
                        raise ValueError("invalid create args")
                    if "group_picture" not in create_args:
                        create_args["group_picture"] = None
                    create_args["group_participants"].append(self.sql_lockable.token_to_id(create_args["token"]))
                    create_args["group_participants"] = list(set(create_args["group_participants"]))
                    ##print("in here")
                    new_chat_id = self.sql_lockable.make_new_chat(create_args["group_name"], create_args["group_picture"],
                                                             create_args["group_type"],
                                                             create_args["group_participants"], self.sql_lockable.token_to_id(create_args["token"]))
                    for user_id in create_args["group_participants"]:
                        self.sql_lockable.update_user_chats(user_id, new_chat_id)
                    ##print(new_chat_id)
                    return new_chat_id
                elif create_args["group_type"] == "2":
                    if "other_id" not in create_args:
                        raise ValueError("invalid create args - missing other_id")
                    other_id = create_args["other_id"]
                    creator_id = self.sql_lockable.token_to_id(create_args["token"])
                    if other_id == creator_id:
                        raise ValueError("invalid create args - cant create one on one chat with yourself")
                    # check if other user even exists
                    if not self.sql_lockable.is_user_exists(other_id):
                        raise ValueError("invalid create args - other user doesnt exist")
                    # check if group like this already exists -
                    if self.sql_lockable.is_exist_oneonone_chat(creator_id, other_id):
                        raise ValueError("invalid create args - one on one chat like this already exists")
                    newid = self.sql_lockable.make_new_chat("", "", 2, [other_id, creator_id], creator_id)
                    for user_id in [other_id, creator_id]:
                        self.sql_lockable.update_user_chats(user_id, newid)
                    return newid
            case "msg":
                if "group_id" not in create_args or "msg_content" not in create_args or "token" not in create_args:
                    raise ValueError(
                        f"invalid create args - missing group_id or msg_content or token. create args is {create_args}")
                user_id = self.sql_lockable.token_to_id(create_args["token"])
                if user_id not in self.sql_lockable.get_group_participants(create_args["group_id"]):
                    print(user_id)
                    print(self.sql_lockable.get_group_participants(create_args["group_id"]))
                    raise messages.AuthError("user not in group")
                if "attachments" not in create_args:
                    create_args["attachments"] = None
                else:
                    for attach in create_args["attachments"]:
                        print(attach)
                if "msg_type" not in create_args:
                    create_args["msg_type"] = "text"
                if "time_sent" not in create_args:
                    create_args["time_sent"] = time.time()
                return self.sql_lockable.save_new_msg(create_args["group_id"], user_id, create_args["msg_content"],
                                                 create_args["time_sent"], create_args["msg_type"],
                                                 create_args["attachments"])

    def do_login(self, login_args: dict, ip_addr : str) -> dict | str:
        """
        function that handles login requests
        :param login_args: the arguements for the login request
        :param ip_addr: the ip address that did the login request
        :return: the response to the login request
        """
        if "2fa-token" in login_args and "2fa-code" in login_args:  # got 2fa. no need for password or email
            if "id" not in login_args:
                raise ValueError("invalid login args")
            id = login_args["id"]
            if not self.sql_lockable.is_user_exists(id):
                raise ValueError("user doesnt exist")
            if login_args["2fa-token"] != self.sql_lockable.get_latest_2fa_token(id):
                raise ValueError("invalid 2fa token")
            if login_args["2fa-code"] != self.sql_lockable.get_last_code(id):
                code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                self.sql_lockable.save_last_code(id, code)
                send_email_2fa(self.sql_lockable.get_email_of_user(id), code)
                raise ValueError("wrong code! new one sent")
            newtoken = self.sql_lockable.set_and_get_new_token(id,ip_addr)
            if "isserver" in login_args:
                self.sql_lockable.set_server_token(newtoken)
            return newtoken

        if "email" not in login_args and "password" not in login_args:
            raise ValueError("invalid login args")
        if self.sql_lockable.check_password_email_match(login_args["email"], login_args["password"]):
            if self.sql_lockable.is_user_enabled(login_args["email"], login_args["password"]):
                id = self.sql_lockable.get_id_from_email_and_password(login_args["email"], login_args["password"])
                if ("2fa-token" not in login_args):  # first step of 2fa
                    newtok = self.sql_lockable.set_new_2fa_token(id)
                    code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                    self.sql_lockable.save_last_code(id, code)
                    send_email_2fa(login_args["email"], code)
                    return {"need": "2fa", "email_sent": login_args["email"], "2fa-token": newtok,
                            "id": self.sql_lockable.get_id_from_email_and_password(login_args["email"],
                                                                                   login_args["password"])}
                if ("2fa-code" != self.sql_lockable.get_last_code(id) or "2fa-token" != self.sql_lockable.get_latest_2fa_token(
                        id)):
                    code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                    self.sql_lockable.save_last_code(id, code)
                    send_email_2fa(login_args["email"], code)
                    raise ValueError("invalid code! or token")
                return self.sql_lockable.set_and_get_new_token(
                    self.sql_lockable.get_id_from_email_and_password(login_args["email"], login_args["password"]), ip_addr)
            raise messages.AuthError("user not enabled")
        else:
            raise messages.AuthError("wrong email or password")

    def do_update(self, update_args : dict):
        """
        function that handles the update requests
        :param update_args: the arguements for the update request
        :return: the id of the updated object
        """
        if "type" not in update_args:
            raise ValueError("invalid update args")
        update_type = update_args["type"]
        match update_type:
            case "user-info-public":
                if "token" not in update_args:
                    raise messages.AuthError("missing token")
                if not self.sql_lockable.is_token_exists(update_args["token"]):
                    raise messages.AuthError("token is invalid")
                uid = self.sql_lockable.token_to_id(update_args["token"])
                if not self.sql_lockable.is_user_exists(uid):
                    raise messages.AuthError("user doesnt exist?")
                if "new_name" not in update_args:
                    raise ValueError("missing new name")
                if "new_image_b64" not in update_args:
                    raise ValueError("missing new image b64")
                if update_args["new_image_b64"] == default_image.DEFAULT_CHAT_IMAGE:
                    update_args["new_image_b64"] = ""
                self.sql_lockable.update_user_info(uid, update_args["new_name"], update_args["new_image_b64"])
            case "file-finalize":
                if "file_name" not in update_args:
                    raise ValueError("missing file_name!")
                if not os.path.isfile("./files/" + update_args["file_name"]):
                    raise ValueError("file doesnt exist")
                os.chmod("./files/" + update_args["file_name"], S_IREAD | S_IRGRP | S_IROTH)
                return update_args["file_name"]

            case "msg-edit":
                if "token" not in update_args:
                    raise messages.AuthError("missing token")
                if "msg_id" not in update_args:
                    raise ValueError("missing msg id")
                if "new_msg_textcontent" not in update_args:
                    raise ValueError("missing new msg content")
                if "group_id" not in update_args:
                    raise ValueError("missing group id")
                if not self.sql_lockable.is_token_exists(update_args["token"]):
                    raise messages.AuthError("invalid token")
                uid = self.sql_lockable.token_to_id(update_args["token"])
                if not self.sql_lockable.is_user_exists(uid):
                    raise messages.AuthError("invalid user")
                if not self.sql_lockable.is_group_exists(update_args["group_id"]):
                    raise messages.AuthError("group doesnt exist")
                if self.sql_lockable.token_to_id(update_args["token"]) not in self.sql_lockable.get_group_participants(
                        update_args["group_id"]):
                    raise messages.AuthError("user not in group!")
                if not self.sql_lockable.is_message_exists(update_args["group_id"], update_args["msg_id"]):
                    raise ValueError("message doesnt exist")
                if not self.sql_lockable.is_message_sender(update_args["group_id"], update_args["msg_id"], uid):
                    raise messages.AuthError("user is not the sender of the message")
                if not self.sql_lockable.is_message_editable(update_args["group_id"], update_args["msg_id"]):
                    raise messages.AuthError("message is not editable")
                self.sql_lockable.edit_message(update_args["group_id"], update_args["msg_id"],
                                               update_args["new_msg_textcontent"])
                return update_args["msg_id"]

            case "msg-read_receipt":
                if "time_read" not in update_args or "msg_id" not in update_args or "token" not in update_args or "group_id" not in update_args:
                    raise ValueError("invalid update args")
                user_id = self.sql_lockable.token_to_id(update_args["token"])
                if user_id not in self.sql_lockable.get_group_participants(update_args["group_id"]):
                    raise messages.AuthError("user not in group")
                if not self.sql_lockable.does_message_exist(update_args["group_id"], update_args["msg_id"]):
                    raise ValueError("message does not exist")
                self.sql_lockable.update_msg_read_receipt(user_id, update_args["group_id"], update_args["msg_id"],
                                                          update_args["time_read"])
                return update_args["msg_id"]
            case "user-2fa":
                if "id" not in update_args or "2fa-code" not in update_args:
                    raise ValueError("invalid update args - missing id or 2fa-code")
                if not self.sql_lockable.is_user_exists(update_args["id"]):
                    raise ValueError("invalid userid")
                if (update_args["2fa-token"] != self.sql_lockable.get_latest_2fa_token(update_args["id"])):
                    raise ValueError("invalid 2fa  from do login")
                if (update_args["2fa-code"] != self.sql_lockable.get_last_code(update_args["id"])):
                    code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                    send_email_2fa(self.sql_lockable.get_email_of_user(update_args["id"]), code)
                    self.sql_lockable.save_last_code(update_args["id"], code)
                    raise ValueError("invalid 2fa code. sent new one to the email!")
                self.sql_lockable.delete_code(update_args["id"])
                self.sql_lockable.enable_user(update_args["id"])
            case "msg-delete":
                if "msg_id" not in update_args:
                    raise ValueError("missing msgid!")
                if "token" not in update_args:
                    raise ValueError("missing token!")
                if "group_id" not in update_args:
                    raise ValueError("missing groupid!")
                if not self.sql_lockable.is_token_exists(update_args["token"]):
                    raise messages.AuthError("invalid token")
                if not self.sql_lockable.is_user_exists(self.sql_lockable.token_to_id(update_args["token"])):
                    raise messages.AuthError("invalid user")
                if not self.sql_lockable.is_group_exists(update_args["group_id"]):
                    raise ValueError("invalid group")
                if self.sql_lockable.token_to_id(update_args["token"]) not in self.sql_lockable.get_group_participants(
                        update_args["group_id"]):
                    raise messages.AuthError("user not in group!")
                if not self.sql_lockable.is_message_exists(update_args["group_id"], update_args["msg_id"]):
                    raise ValueError("message does not exist")
                if not self.sql_lockable.is_message_sender(update_args["group_id"], update_args["msg_id"],
                                                           self.sql_lockable.token_to_id(update_args["token"])):
                    raise messages.AuthError("user isnt message sender!")
                message_arg = self.sql_lockable.fetch_msgs(update_args["group_id"], update_args["msg_id"], update_args["msg_id"])
                message_arg = message_arg[0]
                print(message_arg)
                message_attachments = message_arg["attachments"]
                print(message_attachments)
                dir_path = os.path.dirname(os.path.realpath(__file__))
                print(dir_path)
                for attachment in message_attachments:
                    if attachment["type"] != "file":
                        continue
                    file_name = attachment["hash_name"]
                    if is_file_in_use(f'files/{file_name}'):
                        raise messages.AuthError("file is in use")
                for attachment in message_attachments:
                    if attachment["type"] != "file":
                        continue
                    file_name = attachment["hash_name"]
                    shutil.rmtree(f'files/{file_name}',  ignore_errors = True)
                self.sql_lockable.delete_message(update_args["group_id"], update_args["msg_id"])
            case "user-add-group":
                if "token" not in update_args:
                    raise ValueError("missing token!")
                if "new_user_id" not in update_args:
                    raise ValueError("missing the new user id")
                if "group_id" not in update_args:
                    raise ValueError("missing group_id!")
                if not self.sql_lockable.is_token_exists(update_args["token"]):
                    raise messages.AuthError("token does not exist")
                adder_id = self.sql_lockable.token_to_id(update_args["token"])
                group_participants = self.sql_lockable.get_group_participants(update_args["group_id"])
                print(group_participants)
                print(adder_id)
                if str(adder_id) not in group_participants and int(adder_id) not in group_participants:
                    raise messages.AuthError("user is not in group!")
                group_metadata = self.sql_lockable.get_group_data(update_args["group_id"])["metadata"]
                print(group_metadata)
                if adder_id not in group_metadata["admins"]:
                    raise messages.AuthError("user isnt admin in group!")
                print("user is admin in group")
                group_type = self.sql_lockable.get_group_data(update_args["group_id"])["type"]
                if group_type == "2" or group_type == 2:
                    raise ValueError("user cannot be added to a one on one chat")
                self.sql_lockable.add_user_to_group(update_args["group_id"], update_args["new_user_id"])
        pass

    def do_fetch_chunk(self, fetch_args : dict) -> dict | list:
        """
        function that handles requests to fetch a chunk of something
        :param fetch_args: the arguements for the request
        :return: the chunk of data
        """
        if "type" not in fetch_args:
            raise ValueError("invalid fetch args")
        fetch_type = fetch_args["type"]
        match fetch_type:
            case "file":
                if "file_hash" not in fetch_args:
                    raise ValueError("invalid fetch args")
                if self.do_fetch_chunk_file_pointer is None:
                    self.do_fetch_chunk_file_pointer = open(f"files/{fetch_args['file_hash']}", "rb")
                file_data = self.do_fetch_chunk_file_pointer.read(CHUNK_SIZE)
                ###print({"type" : "file", "is_end" : len(file_data) == 0, "file_data" : base64.b64encode(file_data).decode('utf8')})
                print(len(file_data))
                if len(file_data) == 0:
                    self.do_fetch_chunk_file_pointer.close()
                    self.do_fetch_chunk_file_pointer = None
                return [{"file_hash": fetch_args["file_hash"], "type": "file", "is_end": len(file_data) == 0,
                         "len": len(file_data), "file_data": base64.b64encode(file_data).decode('utf8')}]

    def do_signout(self, token : str) -> None:
        """
        function that sets the token as unusable
        :param token: the token to set as unusable
        :return: None
        """
        self.sql_lockable.set_token_unusable(token)

    @staticmethod
    def return_fetch_success(data) -> dict:
        """
        function that returns a success fetch message
        :param data: the fetch data
        :return: the dict of the message
        """
        return {"success" : "1", "fetch-data" : data}

    @staticmethod
    def return_empty_success() ->dict:
        """
        function that returns an empty success message
        :return: empty success message dict
        """
        return {"success" : "1"}

    @staticmethod
    def return_create_data(data) -> dict:
        """
        function that returns a success create message with the create data
        :param data: the create data
        :return: the dict of the message
        """
        return {"success" : "1", "create-data" : data}

    @staticmethod
    def return_error_message(data) -> dict:
        """
        function that returns an error message dict
        :param data: the error data
        :return: a dict of the error message
        """
        return {"success" : "0", "error-data" : data}


    @staticmethod
    def decode_string(string: str) -> dict:
        """
        decode a string to dict
        :param string: string to decode
        :return: dict of decoded string
        """
        return json.loads(string)

    @staticmethod
    def encode_string(dict: dict) -> str:
        """
        encode a dict to string
        :param dict: dict to encode
        :return: string of encoded dict
        """
        return json.dumps(dict)

    @staticmethod
    def return_chunk_fetch_sucess(data):
        """
        function that returns a success chunk fetch message
        :param data: the chunk of data that was fetched
        :return: the dict of the message
        """
        return {"type" : "fetch-chunks-server", "chunks" : data}


    def __init__(self, broadcaster_instance: BroadCaster, sock: socket.socket,
                            sql_lockable: dataBaseClass.LockableSqliteConnection, voip_server):
        """
        constructor for the user_handler object
        :param broadcaster_instance: the broadcaster instance to use
        :param sock: the messageprot object to use
        :param sql_lockable: the sql lockable object to use
        :param voip_server: the voip server to use
        """
        thread_message_prot = messageProt.messageProt(sock)
        self.broadcaster = broadcaster_instance
        self.sql_lockable = sql_lockable
        self.sock = thread_message_prot
        self.voip_server = voip_server
        self.do_fetch_chunk_file_pointer = None
        self.log = logging.getLogger(__name__)

    def rsa_aes_key_exchange(self):
        """
        function that handles the rsa and aes key exchange
        :return: None
        """
        key_exchange_message_start = {"type": "key-exchange",
                         "my_public_rsa": messageProt.messageProt.keyPair.publickey().export_key().decode()} #first message that server sends to user in the key exchange
        self.sock.send_msg(json.dumps(key_exchange_message_start), 0) #sending the previous message, not encrypted
        their_answer, seq = self.sock.recv_msg() #recieving their answer to the previous message. the answer will be encrypted using the public rsa key
        their_answer_binary = base64.b64decode(their_answer) #decoding their answer from b64 (since rsa encrypts binary, we convert the encrypted binary to b64 and here we make it back to binary)
        their_answer_decrypted = messageProt.messageProt.decryptor.decrypt(ast.literal_eval(str(their_answer_binary))).decode() #here we decode the encrypted binary using our private rsa key
        their_json = json.loads(their_answer_decrypted) #were loading their message that is already decoded
        their_aes = base64.b64decode(their_json["aes-key"]["aes_key"])
        self.sock.set_aes_key(their_aes)
        their_msg, seq = self.sock.recv_msg()

    def main_loop(self):
        """
        the main loop of the user_handler object. each message will be recieved and handled from here
        :return: None
        """
        try:
            while True:
                (new_message_string, seq) = self.sock.recv_msg()
                print(new_message_string)
                message_dict = user_handler_object.decode_string(new_message_string)
                try:
                    message_type = message_dict["type"]
                    if f"{message_type}-args" not in message_dict:
                        raise ValueError(f"missing {message_type} args")
                    if "token" in message_dict[f"{message_type}-args"]:
                        token = message_dict[f"{message_type}-args"]["token"]
                        if self.sql_lockable.get_token_ip(token) != self.sock.get_ip():
                            raise messages.AuthError("token does not match ip!")
                    match message_type:
                        case "fetch":
                            if "fetch-args" not in message_dict:
                                raise ValueError("missing fetch args")
                            fetch_args = message_dict["fetch-args"]
                            fetch_data = self.do_fetch(fetch_args)
                            message_string = user_handler_object.encode_string(user_handler_object.return_fetch_success(fetch_data))
                            self.sock.send_msg(message_string, seq)
                        case "create":
                            if "create-args" not in message_dict:
                                raise ValueError("missing create args")
                            create_args = message_dict["create-args"]
                            new_id = self.do_create(create_args)
                            message_string = user_handler_object.encode_string(user_handler_object.return_create_data(new_id))
                            self.sock.send_msg(message_string, seq)
                            self.broadcaster.new_event(create_args["type"], {"new_id" : new_id, "create-args" : message_dict["create-args"]}, self.sql_lockable)
                        case "login":
                            if "login-args" not in message_dict:
                                raise ValueError("missing login args")
                            login_args = message_dict["login-args"]
                            latest_token = self.do_login(login_args, self.sock.get_ip())
                            if isinstance(latest_token, dict):
                                self.sock.send_msg(user_handler_object.encode_string(user_handler_object.return_fetch_success({"token" : latest_token})), seq)
                            else:
                                latest_id = self.sql_lockable.token_to_id(latest_token)
                                self.sock.send_msg(user_handler_object.encode_string(user_handler_object.return_fetch_success({"token" : latest_token, "id" : latest_id})), seq)
                                token = self.broadcaster.remove_from_available_list(self.sock)
                                if token:
                                    self.do_signout(token)
                                self.broadcaster.add_to_available_list(latest_id, latest_token, self.sock)
                        case "update":
                            if "update-args" not in message_dict:
                                raise ValueError("missing update args")
                            update_args = message_dict["update-args"]
                            updated_id = self.do_update(update_args)
                            message_string = user_handler_object.encode_string(user_handler_object.return_empty_success())
                            self.sock.send_msg(message_string, seq)
                            self.broadcaster.new_event(update_args["type"], {"updated_id" : updated_id, "update-args" : message_dict["update-args"]}, self.sql_lockable)
                        case "fetch-chunks":
                            if "fetch-chunks-args" not in message_dict:
                                raise ValueError("missing fetch chunks args")
                            fetch_data = self.do_fetch_chunk(message_dict["fetch-chunks-args"])
                            while(all(list(map(lambda x: x["is_end"], fetch_data))) is False):
                                message_string = user_handler_object.encode_string(user_handler_object.return_chunk_fetch_sucess(fetch_data))
                                self.sock.send_msg(message_string, 0)
                                fetch_data = self.do_fetch_chunk(message_dict["fetch-chunks-args"])
                            message_string = user_handler_object.encode_string(user_handler_object.return_chunk_fetch_sucess(fetch_data))
                            self.sock.send_msg(message_string, 0)
                        case _:
                            raise TypeError("invalid message type")
                except (TypeError, ValueError, messages.AuthError) as e:
                    message_string = user_handler_object.encode_string(user_handler_object.return_error_message(str(e)))
                    self.sock.send_msg(message_string, seq)
                    continue
                except Exception as e: #if getting this - something is wrong, and we need to document it
                    print("GOT EXCEPTIONNNNNNNNNN")
                    traceback.print_exc()
        except TypeError:
            exit()
        except Exception:
            self.log.warning(traceback.format_exc())
        finally:
            token = self.broadcaster.remove_from_available_list(self.sock)
            if (token and self.sql_lockable.get_token_type(token)) != "server":
                self.do_signout(token)
            else:
                print("supposadly server token type?")












def start_thread(broadcaster_instance, socket, sql_lockable, voip_server):
    """
    the start function of the thread. will handle setting up the object
    :param broadcaster_instance: the broadcaster instance to use in the thread
    :param socket: the messageprot instance to use in the thread
    :param sql_lockable: the sql lockable instance to use in the thread
    :param voip_server: the voip server instance to be used in the thread
    :return:
    """
    user_handler = user_handler_object(broadcaster_instance, socket, sql_lockable, voip_server)
    user_handler.rsa_aes_key_exchange()
    user_handler.main_loop()