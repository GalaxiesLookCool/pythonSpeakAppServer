import socket
import json
import messageProt
import dataBaseClass
import threading
import datetime
import time

import messages
import traceback
import user_handler

from pycallgraph2 import PyCallGraph
from pycallgraph2.output import GraphvizOutput

import sqlite3
from sqlite3 import Error

import signal
import sys


def func(signum, frame):
    print (f"You raised a SigInt! Signal handler called with signal {signum}")
    raise Exception("should quit")

signal.signal(signal.SIGINT, func)

HOSTBIND = "0.0.0.0"

HOSTPORT = 8969


def createConn():
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketServer.bind((HOSTBIND, HOSTPORT))
    socketServer.listen(1)
    return socketServer




sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY,
                                        email text NOT NULL,
                                        uname text NOT NULL,
                                        arrayOfChats text,
                                        password text NOT NULL,
                                        picture text
                                    ); """
sql_create_chats_table = """ CREATE TABLE IF NOT EXISTS chats (
                                        id integer PRIMARY KEY,
                                        name text,
                                        groupmembersbyid text,
                                        picture text,
                                        type int                                        
                                    ); """

sql_create_tokens_table = """ CREATE TABLE IF NOT EXISTS tokens (
                                        id integer PRIMARY KEY,
                                        token text NOT NULL,
                                        timeissued text NOT NULL,
                                        timestopped text,
                                        userid integer NOT NULL
                                    ); """


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(traceback.format_exc())
        print(e)

def loginHandler(sock, dbo, clientMap, clientLock):
    """
    function that handles the specific login/registering messages
    :param sock: a socket object
    :param dbo: an sqllite object
    :param resultArr: an array that the result of the thread will be stored in
    """
    try:
        (identMsg, seq) = messageProt.messageProt.recv_msg(sock)
    except OSError:
        print(traceback.format_exc())
        print("quitting thread")
        return
    except Exception as e:
        return loginHandler(sock, dbo ,clientMap, clientLock)
    identMsg = json.loads(identMsg.decode(errors='ignore'))
    print(identMsg)
    if (identMsg["type"] == "LOGIN"):
        (id, token) = dataBaseClass.doLogin(dbo, identMsg["email"], identMsg["pswd"])
        print(f"id - {id} , token - {token}")
        messageProt.messageProt.send_msg(sock, json.dumps({"success" : "1" if len(token) == 20 else "0", "token" : token, "id" : id}), seq)
        if len(token) == 20:
            # User.updateUSERON(self._dbo, identMsg["uname"], 1)
            print(f"id is {id}")
            with clientLock:
                if not str(id) in clientMap:
                    clientMap[str(id)] = [sock]
                else:
                    clientMap[str(id)].append(sock)
            return (token, id)
        return loginHandler(sock, dbo ,clientMap, clientLock)

    else:
        if (identMsg["type"] == "SIGNUP"):
            if not ("email" in identMsg and "uname" in identMsg and "pswd" in identMsg and "pfp" in identMsg):
                messageProt.messageProt.send_msg(sock, json.dumps({"success" : "0","errorMsg" : "invalid list of arguements - must include email field, uname field, pswd field, and a pfp field" }))
                return loginHandler(sock, dbo ,clientMap, clientLock)
            isSuccess = dataBaseClass.doSignup(dbo, identMsg["email"], identMsg["uname"], identMsg["pswd"], identMsg["pfp"])
            print(isSuccess)
            if isSuccess:
                messageProt.messageProt.send_msg(sock, json.dumps({"success" : "1"}), seq)
                return loginHandler(sock, dbo ,clientMap, clientLock)
            messageProt.messageProt.send_msg(sock, json.dumps({"success" : "0", "errorMsg" : "database error"}), seq)
            return loginHandler(sock, dbo ,clientMap, clientLock)



def main():
    lsc = dataBaseClass.LockableSqliteConnection(r"pythonsqlite.db")
    brdcstr = user_handler.BroadCaster()
    # create tables
    with lsc:
        create_table(lsc.connection,sql_create_users_table)
        create_table(lsc.connection, sql_create_chats_table)
        create_table(lsc.connection, sql_create_tokens_table)


    clientMap = dict()
    clientLock = threading.Lock()
    newSocket = createConn()
    while True:
        try:
            print("trying to get a client")
            (clientsocket, address) = newSocket.accept()
            print("got a new client")
            print(address)
            newSocketThread = threading.Thread(target=user_handler.handler_thread_function, args=(brdcstr, clientsocket, lsc,))
            newSocketThread.start()
        except KeyboardInterrupt:
            print("trying to press ctrl C")
        except Exception as e:
            print(str(e))

if __name__ == "__main__":
    main()
