#!/usr/bin/python3
import socket
from support import recvMessage,sendMessage,TooMuchData
(HOST,PORT)=('127.0.0.1',1337)

def testServer():
    serverSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSocket.connect((HOST,PORT))
    sendMessage(serverSocket,b'update_graph')
    sendMessage(serverSocket,b'initiate_zkn')
if __name__=="__main__":
    testServer()