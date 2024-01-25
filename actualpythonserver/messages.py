import json
import dataBaseClass
import logging
import messageProt
import socket

log = logging.getLogger(__name__)


class AuthError(Exception):
    pass


def get_create_type(msg_dict : dict) -> str:
    return ""

def is_message_create(msg_dict : dict) -> bool:
    return False
def is_message_fetch(msg_dict : dict) -> bool:
    return False

def decode_string(message_string : str) -> dict:
    return json.loads(message_string)

def get_query_type(msg_dict : dict) -> str:
    return ""

def encode_dict(message_dict : dict) -> str:
    return json.dumps(message_dict)

class MessageFactory:
    def __init__(self, sql_lockable: dataBaseClass.LockableSqliteConnection):
        self.sql_lockable = sql_lockable

    @staticmethod
    def send(sock: socket.socket, message: dict, sequence_number: int = 0) -> None:
        messageProt.messageProt.send_msg(sock, json.dumps(message), sequence_number)

    @staticmethod
    def recv(sock: socket.socket) -> tuple:
        log.warning("recieving")
        message_tuple = messageProt.messageProt.recv_msg(sock)
        log.warning(message_tuple)
        if len(message_tuple) == 0:
            raise OSError("socket disconnected!")
        log.warning("returning")
        return message_tuple[0].decode(), message_tuple[1]

    def get_from_json(self, message: str):
        message_data = json.loads(message)
        return self.make_from_dict(message_data)

    def make_from_dict(self, message_map: dict):
        match message_map["type"]:
            case "image-register":
                return RegisterMessage(message_map["email"], message_map["password"], message_map["username"],
                                       message_map["image"], self.sql_lockable)
            case "plain-register":
                return RegisterMessage(message_map["email"], message_map["password"], message_map["username"],
                                       "", self.sql_lockable)
            case "plain-login":
                return LoginMessage(message_map["email"], message_map["password"], self.sql_lockable)
            case "plain-logout":
                return LogOutMessage(message_map["token"], self.sql_lockable)
            case "fetch-groups":
                return GroupsQueryMessage(message_map["token"], self.sql_lockable)
            case _:
                raise TypeError("invalid message type")

    @staticmethod
    def encode_string(message_data: dict) -> str:
        return json.dumps(message_data)
        # match message_data.type:
        # case "update-user-on":
        # return json.dumps(message_data)

    def make_logout_message(self, token: str) -> 'LogOutMessage':
        return LogOutMessage(token, self.sql_lockable)

    @staticmethod
    def make_success_message(success_message: str = "successful-action") -> dict:
        full_message = {"success": "1", "success_message": success_message}
        return full_message

    @staticmethod
    def make_error_message(error_message: str = "failre in server-side") -> dict:
        full_message = {"success": "0", "error_message": error_message}
        return full_message


class BaseMessage:
    def __init__(self, token: str = None, sql_lockable: dataBaseClass.LockableSqliteConnection = None):
        self.lockable_sql = sql_lockable
        self.token = token
        try:
            self.sender_id = sql_lockable.token_to_id(self.token)
        except Exception as e:
            log.error("token is invalid, " + str(e))
            raise ValueError("In correct token!")

    def is_authed(self) -> bool:
        return True

    def save_to_db(self):
        return

    def broadcast_data(self) -> tuple[dict, list]:
        return {"origin-id": self.sender_id}, list()

    def success_return_data(self) -> dict:
        return {"success": "1"}

    def is_broadcastable(self) -> bool:
        return False

    def get_id(self):
        return self.sender_id

    def is_query(self) -> bool:
        return False

    def do_query(self) -> list[dict]:
        return list()


class RegisterMessage(BaseMessage):
    def __init__(self, password: str, email: str, username: str, image_b64: str,
                 sql_lockable: dataBaseClass.LockableSqliteConnection):
        super().__init__(None, sql_lockable)
        self.password = password
        self.email = email
        self.username = username
        self.image = image_b64

    def get_username(self) -> str:
        return self.username

    def get_email(self) -> str:
        return self.email

    def get_password(self) -> str:
        return self.password

    def save_to_db(self):
        self.lockable_sql.save_new_user_to_db(self.email, self.password, self.username, self.image)


class LoginMessage(BaseMessage):
    def __init__(self, email: str, password: str, sql_lockable: dataBaseClass.LockableSqliteConnection):
        super().__init__(None, sql_lockable)
        self.email = email
        self.password = password

    def get_email(self) -> str:
        return self.email

    def get_password(self) -> str:
        return self.password

    def is_authed(self) -> bool:
        # return False if self.lockable_sql.check_password_email_match(self.email, self.password) == False else
        # self.lockable_sql.get_id_from_email_and_password(self.email, self.password)
        if self.lockable_sql.check_password_email_match(self.email, self.password) is False:
            return False
        print("successful auth")
        self.sender_id = self.lockable_sql.get_id_from_email_and_password(self.email, self.password)
        print(self.sender_id)
        return True

    def save_to_db(self):
        self.token = self.lockable_sql.set_and_get_new_token(self.sender_id)
        return self.token

    def success_return_data(self):
        dot_to_return = super().success_return_data()
        dot_to_return["data"] = dict()
        dot_to_return["data"]["token"] = self.token
        dot_to_return["data"]["id"] = self.sender_id
        return dot_to_return

    def is_broadcastable(self) -> bool:
        return True

    def get_token(self) -> str:
        return self.token

    def broadcast_data(self) -> tuple[dict, list]:
        base_dot_map, _ = super().broadcast_data()
        base_dot_map["type"] = "update-user-on"
        base_dot_map["is_user_on"] = True
        return base_dot_map, list()


class LogOutMessage(BaseMessage):

    def is_status_message(self) -> bool:
        return True

    def save_to_db(self):
        self.lockable_sql.set_token_offline(self.token)

    def broadcast_data(self) -> tuple[dict, list]:
        base_dot_map, _ = super().broadcast_data()
        base_dot_map["type"] = "update-user-on"
        base_dot_map["is_user_on"] = False
        return base_dot_map, list()


class GroupsQueryMessage(BaseMessage):
    def is_query(self) -> bool:
        return True

    def do_query(self) -> None:
        groups_ids_list = self.lockable_sql.fetch_group_ids(self.token)
        response_list = list()
        for group_id in groups_ids_list:
            response_list.append(GroupData(self.token, *self.lockable_sql.get_group_data(group_id)))

    def success_return_data(self) -> list[dict]:
        pass


class GroupData(BaseMessage):
    def __init__(self, token: str, group_name: str, group_image: list,  group_type: str, group_id : str, group_members : str,
                 sql_lockable: dataBaseClass.LockableSqliteConnection):
        super().__init__(token, sql_lockable)
        self.group_image = group_image
        self.group_name = group_name
        self.group_type = group_type
        self.group_id = group_id
        self.members = json.loads(group_members)

    def success_return_data(self) -> dict:
        return {"group_type": self.group_type, "group_id": self.group_id, "group_name": self.group_name,
                 "group_members" : self.members}
