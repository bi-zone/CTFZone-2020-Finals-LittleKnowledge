#!/usr/bin/python3
import socket
import threading
import logging
import sys
import os
from ctypes import *
from support import * 
(HOST,PORT)=('127.0.0.1',1337)
verifier=Verifier(128,64,4)

def update_graph(clientSocket):
    global verifier
    initial_setting_packet=verifier.getInitialSettingPacket()
    sendMessage(clientSocket,initial_setting_packet)
    graphPacket=recvMessage(clientSocket)
    encrypted_signature=recvMessage(clientSocket)
    if verifier.updateZKnGraph(graphPacket,encrypted_signature)==0:
        sendMessage(clientSocket,"SUCCESS")
    else:
        sendMessage(clientSocket,"ERROR")
    

def start_zkn(clientSocket):
    global verifier
    protocol_verifier=ZKNProtocolVerifier(verifier)
    while True:
        command=recvMessage(clientSocket)
        if command==b"get_configuration":
            configuration_packet=protocol_verifier.createProofConfigurationPacket()
            if configuration_packet==None:
                sendMessage(clientSocket,"ERROR")
                continue
            sendMessage(clientSocket,configuration_packet)
        elif command==b"save_commitment":
            commitment_packet=recvMessage(clientSocket)
            status=protocol_verifier.saveCommitment(commitment_packet)
            if status==0:
                sendMessage(clientSocket,"SUCCESS")
            else:
                sendMessage(clientSocket,"ERROR")
        elif command==b"create_challenge":
            challenge_packet=protocol_verifier.createChallenge()
            if challenge_packet==None:
                sendMessage(clientSocket,"ERROR")
                continue
            sendMessage(clientSocket,challenge_packet)
        elif command==b"check_proof":
            revealPacket=recvMessage(clientSocket)
            (result,additional)=protocol_verifier.checkProof(revealPacket)
            if result==0:
                sendMessage(clientSocket,"SUCCESS")
                sendMessage(clientSocket,additional)
            else:
                sendMessage(clientSocket,"ERROR")
                if additional==1:
                    sendMessage(clientSocket,"SYSTEM_ERROR")
                elif additional==2:
                    sendMessage(clientSocket,"PWN_ATTEMPT_DETECTED (Really? This is not that kind of task)")
                elif additional==3:
                    sendMessage(clientSocket,"TOO_EARLY (Complete previous stages)")
                elif additional==4:
                    sendMessage(clientSocket,"CHEATING_DETECTED")
                else:
                    sendMessage(clientSocket,"UNKNOWN_ERROR")
        elif command==b"exit_protocol":
            sendMessage(clientSocket,"EXITING_PROOF")
            del protocol_verifier
            return
        else:
            sendMessage(clientSocket,"BAD_COMMAND")
            del protocol_verifier
            return



def handleConnection(clientSocket):
    global verifier
    try:
        while True:
            try:
                command=recvMessage(clientSocket)
            except TooMuchData:
                return
            if command==b'update_graph':
                sendMessage(clientSocket,"STARTING_UPDATE")
                update_graph(clientSocket)
                continue
            elif command==b'start_zkn_protocol':
                sendMessage(clientSocket,"STARTING_PROTOCOL")
                start_zkn(clientSocket)
                continue
            elif command==b'exit':
                sendMessage(clientSocket,"GOODBYE")
                clientSocket.close()
                break
            else:
                print('Unknown command. Closing connection')
                clientSocket.close()
                break
    except (TooMuchData, NotEnoughData):
        logging.error('Received malformed packet')
        clientSocket.close()
        return

    except ConnectionResetError:
        logging.error('Connection reset by client')
        return
    clientSocket.close()



def startServer():

    serverSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    serverSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
    serverSocket.bind((HOST,PORT))
    serverSocket.listen()
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='team_server.log',
                    filemode='w')
    logging.info(f'Started listenning on {HOST}:{PORT}')
    while True:

        try:
            (clientSocket,address)=serverSocket.accept()
            logging.info(f'Accepted connection from {address}')
            threading.Thread(target=handleConnection,
                            args=(clientSocket,)).start()
        except KeyboardInterrupt:
            print ('Exiting...')
            return
        except Exception as e:
            print (f'Caught exception: {repr(e)}',file=sys.stderr)
if __name__=="__main__":
    startServer()