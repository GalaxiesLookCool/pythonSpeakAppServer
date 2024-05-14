import os
import socket
import json
import messageProt
import dataBaseClass
import threading
import datetime
import time

import messages
import traceback
#import user_handler

import sqlite3
from sqlite3 import Error

import signal
import sys

import user_handler
from voip_server import voip_server_class
from user_handler_oop import start_thread

def func(signum, frame):
    """
    function that handles the SIGINT signal
    :param signum: the signum
    :param frame: and the frane
    :return: nothing, but raises exception (this is for catching the exit signal)
    """
    print (f"You raised a SigInt! Signal handler called with signal {signum}")
    raise Exception("should quit")

signal.signal(signal.SIGINT, func)

HOSTBIND = "0.0.0.0"

HOSTPORT = 8969


def createConn():
    """
    function that creates a socket object and binds and listens to it
    :return: the socket
    """
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
                                        picture text,
                                        enabled integer NOT NULL,
                                        lastcode text,
                                        lastissuedtoken text
                                    ); """
sql_create_chats_table = """ CREATE TABLE IF NOT EXISTS chats (
                                        id integer PRIMARY KEY,
                                        name text,
                                        groupmembersbyid text,
                                        picture text,
                                        type int,
                                        metadata text DEFAULT '{}'                                 
                                    ); """

sql_create_tokens_table = """ CREATE TABLE IF NOT EXISTS tokens (
                                        id integer PRIMARY KEY,
                                        token text NOT NULL,
                                        timeissued text NOT NULL,
                                        timestopped text,
                                        userid integer NOT NULL,
                                        tokentype text,
                                        ip text
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


def main():
    """
    main function - entry point
    :return: none
    """
    lsc = dataBaseClass.LockableSqliteConnection(r"pythonsqlite.db")
    brdcstr = user_handler.BroadCaster()

    voip_handler = voip_server_class()
    new_voip_thread = threading.Thread(target=voip_handler.run)
    new_voip_thread.start()

    files_folder = 'files'
    if not os.path.exists(files_folder):
        os.makedirs(files_folder)

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
            newSocketThread = threading.Thread(target=start_thread, args=(brdcstr, clientsocket ,lsc, new_voip_thread))
            #newSocketThread = threading.Thread(target=user_handler.handler_thread_function, args=(brdcstr, clientsocket, lsc, callhandler))
            newSocketThread.start()
        except KeyboardInterrupt:
            print("trying to press ctrl C")
        except Exception as e:
            print(str(e))

if __name__ == "__main__":
    main()
