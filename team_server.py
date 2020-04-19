#!/usr/bin/python3
import socket
import threading
import sys
import os
from ctypes import *
from support import recvMessage,sendMessage,TooMuchData
(HOST,PORT)=('127.0.0.1',1337)
ZKNLIBRARY_NAME='./libzkn.so'
zknlib=0
flag_storage={}
def initializeZKNState():
    global zknlib
    defaultVerticeCount=16
    return zknlib.initializeZKNThread(c_uint16(defaultVerticeCount))
def destroyZKNState(state):
    global zknlib
    zknlib.destroyZKNThread(state)

def updateGraph(clientSocket):
    #Choose Params
    #Receive graph
    #Receive graph sign
    #Receive graph id
    #Check graph norm
    pass

def updateFlag(clientSocket):
    #Receive flag
    #Receive flag id
    #Receive signature 
    #Check signature
    pass
def initiateZKn(clientSocket):
    #Choose Interactive/Parallel
    #
    pass

def handleConnection(clientSocket):
    zkn_state=initializeZKNState()
    try:
        while True:
            try:
                command=recvMessage(clientSocket)
                
            except TooMuchData:
                return
            if command=='update_graph':
                print ('Updating graph')
                updateGraph(clientSocket)
                continue
            elif command=='update_flag':
                print ('Updating flag')
                continue
            elif command=='initiate_zkn':
                print ('Initiating ZKN')
                initiateZKn(clientSocket)
                continue
            else:
                print('Unknown command. Closing connection')
                clientSocket.close()
                break
        
    except Exception as e:
        destroyZKNState(zkn_state)
        raise e
   destroyZKNState(zkn_state)


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