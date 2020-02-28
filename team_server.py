#!/usr/bin/python3
import socket
import threading
import sys
import os
from ctypes import *
from support import recvMessage,sendMessage,TooMuchData
(HOST,PORT)=('127.0.0.1',1337)
ZKNLIBRARY_NAME='./libzkn.so'
def initializeZKNState():
    pass

def updateGraph(clientSocket):
    pass

def initiateZKn(clientSocket):
    pass

def handleConnection(clientSocket):
    zkn_state=initializeZKNState()
    while True:
        try:
            command=recvMessage(clientSocket)
            
        except TooMuchData:
            return
        if command=='update_graph':
            print ('Updating graph')
            updateGraph(clientSocket)
            continue
        elif command=='initiate_zkn':
            print ('Initiating ZKN')
            initiateZKn(clientSocket)
            continue
        else:
            print('Unknown command. Closing connection')
            clientSocket.close()
            break
       
    return

class ZKNLibNotFound(Exception):pass
class ZKNLibNotALib(Exception):pass
def loadZKNLibrary():
    if not os.path.isfile(ZKNLIBRARY_NAME):
        raise ZKNLibNotFound 
    global zknlib
    try:
        zknlib=cdll.LoadLibrary(ZKNLIBRARY_NAME)
    except OSError:
        raise ZKNLibNotALib

    zknlib.test()

def startServer():
    loadZKNLibrary()
    serverSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    serverSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
    serverSocket.bind((HOST,PORT))
    serverSocket.listen()
    while True:
        (clientSocket,address)=serverSocket.accept()
        try:
            threading.Thread(target=handleConnection,
                            args=(clientSocket,)).start()
        except KeyboardInterrupt:
            return
        except Exception as e:
            print (f'Caught exception: {repr(e)}',file=sys.stderr)
if __name__=="__main__":
    startServer()