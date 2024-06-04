import json
import socket
import time

import dataBaseClass
import messageProt
import logging
import threading
from voip_server import voip_server_class

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024
class BroadCaster:
    def __init__(self):
        """
        init function for BroadCaster class
        :return: none
        """
        self.data_lock = threading.Lock()
        self.users_dict = dict()

    def get_user_aes_key(self, uid, token):
        """
        function to get the user aes key given the user id and token
        :param uid: user id of user
        :param token: token of user (as one user id can have multiple connections with different tokens and aes keys at the same time)
        :return: the aes key of the user
        """
        print(self.users_dict)
        for sock, user_token in self.users_dict[str(uid)]:
            if user_token == token:
                return sock.aes_key

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
            case "user-add-group":
                group_id = event_data["update-args"]["group_id"]
                target_ids = sql_lockable.get_group_participants(group_id)
                group_data = sql_lockable.get_group_data(group_id)
                group_data["latest_msg"] = sql_lockable.get_latest_message(group_id)
                new_message = {"type" : "server-update", "update-data" : {"type" : "user-added", "group_id" : group_id, "group-data" : group_data}}
                for uid in target_ids:
                    if uid in self.users_dict:
                        print("printing self users dict::::::::::::\n\n\n\n")
                        print(self.users_dict)
                        print("\n\n\n\nprinting self users dict::::::::::::")
                        for sock, _ in self.users_dict[uid]:
                            try:
                                newThread = threading.Thread(target=messageProt.messageProt.send_msg,
                                                             args=(sock, json.dumps(new_message)))
                                newThread.start()
                                # messageProt.messageProt.send_msg(sock, json.dumps(new_message))
                            except Exception as e:
                                pass
                                # print(f"error sending msg to {uid}")
            case "call-update-user-logout":
                call_id = event_data["update-args"]["call-id"]
                group_id = event_data["update-args"]["group_id"]
                uid = event_data["update-args"]["user-id"]
                #current_call_status = self.call_handler.get_group_data(group_id)
                new_message = {"type" : "server-update", "update-data" : {"type" : "call-update-user-logout", "group_id" : group_id, "user-id" : uid}}
                target_ids = sql_lockable.get_group_participants(group_id)
                for uid in target_ids:
                    if uid in self.users_dict:
                        print("printing self users dict::::::::::::\n\n\n\n")
                        print(self.users_dict)
                        print("\n\n\n\nprinting self users dict::::::::::::")
                        for sock, _ in self.users_dict[uid]:
                            try:
                                newThread = threading.Thread(target=messageProt.messageProt.send_msg,
                                                             args=(sock, json.dumps(new_message)))
                                newThread.start()
                                # messageProt.messageProt.send_msg(sock, json.dumps(new_message))
                            except Exception as e:
                                pass
                                # print(f"error sending msg to {uid}")
            case "call-over":
                call_id = event_data["update-args"]["call_id"]
                group_id = event_data["update-args"]["group_id"]
                current_call_status = {"is_active" : False}
                new_message = {"type" : "server-update", "update-data" : {"type" : "call-over", "group_id" : group_id}}
                target_ids = sql_lockable.get_group_participants(group_id)
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
                #group_data["activecall"] = self.call_handler.get_group_data(group_id)
                new_message = { "type" : "server-update", "update-data" : {"type" : "new-group", "group-data" : group_data}}
                for uid in group_data["members"]:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            sock.send_msg( json.dumps(new_message))
            case "msg-read_receipt":
                msg_id = event_data["update-args"]["msg_id"]
                group_id = event_data["update-args"]["group_id"]
                target_ids = sql_lockable.get_group_participants(group_id)
                new_message = { "type" : "server-update", "update-data" : {"type" : "msg-read_receipt", "group_id" : group_id, "msg_id" : msg_id, "user_read" : sql_lockable.token_to_id(event_data["update-args"]["token"]), "time_read" : event_data["update-args"]["time_read"]}}
                for uid in target_ids:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            newThread = threading.Thread(target=messageProt.messageProt.send_msg,
                                                         args=(sock, json.dumps(new_message)))
                            newThread.start()
                            #sock.send_msg( json.dumps(new_message))
            case "msg-delete":
                msg_id = event_data["update-args"]["msg_id"]
                group_id = event_data["update-args"]["group_id"]
                target_ids = sql_lockable.get_group_participants(group_id)
                new_message = {"type" : "server-update", "update-data" : {"type" : "msg-delete", "group_id" : group_id, "msg_id" : msg_id}}
                for uid in target_ids:
                    if uid in self.users_dict:
                        for sock,_ in self.users_dict[uid]:
                            sock.send_msg( json.dumps(new_message))
            case "msg-edit":
                edit_time = time.time()
                msg_id = event_data["update-args"]["msg_id"]
                group_id = event_data["update-args"]["group_id"]
                target_ids = sql_lockable.get_group_participants(group_id)
                new_message = {"type" : "server-update", "update-data" : {"type" : "msg-edit", "group_id" : group_id, "msg_id" : msg_id, "new_text" : event_data["update-args"]["new_msg_textcontent"], "edit_time" : edit_time}}
                for uid in target_ids:
                    if uid in self.users_dict:
                        for sock, _ in self.users_dict[uid]:
                            sock.send_msg( json.dumps(new_message))
        #log.warning(f"event type is {event_type}")


    def add_to_available_list(self, user_id: str, token:str ,sock: socket.socket):
        """
        add a user to the available list with its token
        :param user_id: userid
        :param token:  token
        :param sock: socket of user
        :return: none
        """
        user_id = user_id
        with self.data_lock:
            if user_id not in self.users_dict:
                self.users_dict[user_id] = [(sock, token)]
            else:
                self.users_dict[user_id].append((sock, token))

    def remove_from_available_list(self, sock: socket.socket) -> str | None:
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
        return None


