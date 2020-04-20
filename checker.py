#!/usr/bin/python3

from support import *
import socket
import random
import os
import time
flag=b'FLAGGER'
(TEAM_HOST,TEAM_PORT)=('127.0.0.1',1337)
ERROR_CONNECTION_REFUSED=1
ERROR_CONNECTION_RESET=2


ERROR_COULDNT_START_UPDATE=11
ERROR_BAD_INTIAL_SETTINGS=12
ERROR_WITH_GRAPH_CREATION=13
ERROR_WITH_FINISHING_UPDATE=14
ERROR_COULDNT_START_PROTOCOL=15
ERROR_RECEIVING_PROOF_CONFIGURATION=16
ERRONEOUS_PROOF_CONFIGURATION=17
ERROR_COULDNT_CREATE_PROOFS=18
ERROR_COULDNT_CREATE_COMMITMENT_PACKET=19
ERROR_COULDNT_SAVE_COMMITMENT=20
ERROR_COULDNT_CREATE_CHALLENGE=21
ERROR_BAD_CHALLENGE=22
ERROR_UNDEFINED_ON_CORRECT_PROOF=23
ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF=24
ERROR_NOT_PWN=25
ERROR_NOT_EARLY=26
ERROR_NOT_CHEATING=27
ERROR_NOT_UNKNOWN=28
ERROR_WRONG_FLAG=29
ERROR_SHOULD_BE_CHEATING_OR_PWNING=30
ERROR_NOT_EXITING_PROOF=31
ERROR_NOT_EXITING=32

def malform_buffer(buffer, minimum_sequential_change=17):
    strategy=random.randint(0,3)
    if (strategy==1 or strategy==2) and len(buffer)<=minimum_sequential_change:
        strategy=0
    if strategy==0:
        #Replace buffer with random
        return os.urandom(len(buffer))
    elif strategy==1:
        #Replace last min_seq_change with random (to keep headers intact)
        return buffer[:-minimum_sequential_change]+os.urandom(len(buffer))
    elif strategy==2:
        #Replace randomly min_seq_change
        positions=len(buffer)-minimum_sequential_change
        chosen=random.randint(0,positions)
        return buffer[:chosen]+os.urandom(minimum_sequential_change)+buffer[chosen+minimum_sequential_change:]
    elif strategy==3:
        return os.urandom(random.randint(1,len(buffer)))


def check_team_server(HOST,PORT):
    prover=Prover(flag,b'key')
    try:
        #Updating flag and graph
        team_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            team_socket.connect((HOST,PORT))
        except ConnectionRefusedError:
            team_socket.close()
            return ERROR_CONNECTION_REFUSED

        sendMessage(team_socket,"update_graph")
        if recvMessage(team_socket)!=b'STARTING_UPDATE':
            team_socket.close()
            return ERROR_COULDNT_START_UPDATE
        initial_settings=recvMessage(team_socket)
        if not prover.createFullKnowledge(initial_settings):
            team_socket.close()
            return ERROR_BAD_INTIAL_SETTINGS 

        (graphSetPacket, signature)=prover.createGraphSetPacketAndHash(initial_settings)
        if (graphSetPacket)==None:
            team_socket.close()
            return ERROR_WITH_GRAPH_CREATION
        sendMessage(team_socket,graphSetPacket)
        sendMessage(team_socket,signature)
        result=recvMessage(team_socket)
        if result!=b'SUCCESS':
            team_socket.close()
            return ERROR_WITH_FINISHING_UPDATE
        #Finished updating graph and flag. Now need to check

        sendMessage(team_socket,b'start_zkn_protocol')
        if recvMessage(team_socket)!=b'STARTING_PROTOCOL':
            return ERROR_COULDNT_START_PROTOCOL
        sendMessage(team_socket,b'get_configuration')
        proof_configuration=recvMessage(team_socket)
        if (proof_configuration==b'ERROR'):
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            return ERROR_COULDNT_CREATE_PROOFS
        commitment_packet=prover.createCommitmentPacket()
        if commitment_packet==None:
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET
        sendMessage(team_socket,b'save_commitment')
        sendMessage(team_socket,commitment_packet)
        if recvMessage(team_socket)!=b'SUCCESS':
            return ERROR_COULDNT_SAVE_COMMITMENT
        
        sendMessage(team_socket,b'create_challenge')
        challenge=recvMessage(team_socket)
        if challenge==b'ERROR':
            return ERROR_COULDNT_CREATE_CHALLENGE
        revealPacket=prover.createRevealPacket(challenge)
        if revealPacket==None:
            return ERROR_BAD_CHALLENGE
        sendMessage(team_socket,b'check_proof')
        sendMessage(team_socket,revealPacket)
        check_proof_result=recvMessage(team_socket)
        if check_proof_result!=b'SUCCESS':
            if check_proof_result!=b'ERROR':
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
            error_message=recvMessage(team_socket)
            if error_message.find(b'SYSTEM_ERROR')!=-1:
                return ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF
            elif error_message.find(b'PWN_ATTEMPT_DETECTED')!=-1:
                return ERROR_NOT_PWN
            elif error_message.find(b'TOO_EARLY')!=-1:
                return ERROR_NOT_EARLY
            elif error_message.find(b'CHEATING_DETECTED')!=-1:
                return ERROR_NOT_CHEATING
            elif error_message.find(b'UNKNOWN_ERROR')!=-1:
                return ERROR_NOT_UNKNOWN
            else:
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
        received_flag=recvMessage(team_socket)
        if received_flag[:len(flag)]!=flag:
            return ERROR_WRONG_FLAG
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            return ERROR_NOT_EXITING_PROOF
        """
        ##ERROR CHECKS
        sendMessage(team_socket,b'start_zkn_protocol')
        if recvMessage(team_socket)!=b'STARTING_PROTOCOL':
            return ERROR_COULDNT_START_PROTOCOL
        sendMessage(team_socket,b'get_configuration')
        proof_configuration=recvMessage(team_socket)
        if (proof_configuration==b'ERROR'):
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            return ERROR_COULDNT_CREATE_PROOFS
        commitment_packet=prover.createCommitmentPacket()
        if commitment_packet==None:
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET

        sendMessage(team_socket,b'save_commitment')
        sendMessage(team_socket,malform_buffer( commitment_packet))
        if recvMessage(team_socket)!=b'SUCCESS':
            return ERROR_COULDNT_SAVE_COMMITMENT
        
        sendMessage(team_socket,b'create_challenge')
        challenge=recvMessage(team_socket)
        if challenge==b'ERROR':
            return ERROR_COULDNT_CREATE_CHALLENGE
        revealPacket=prover.createRevealPacket(challenge)
        if revealPacket==None:
            return ERROR_BAD_CHALLENGE
        sendMessage(team_socket,b'check_proof')
        sendMessage(team_socket,revealPacket)
        check_proof_result=recvMessage(team_socket)
        if check_proof_result!=b'SUCCESS':
            if check_proof_result!=b'ERROR':
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
            error_message=recvMessage(team_socket)
            if error_message.find(b'SYSTEM_ERROR')!=-1:
                return ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF
            elif error_message.find(b'PWN_ATTEMPT_DETECTED')!=-1:
                return ERROR_NOT_PWN
            elif error_message.find(b'TOO_EARLY')!=-1:
                return ERROR_NOT_EARLY
            elif error_message.find(b'CHEATING_DETECTED')!=-1:
                return ERROR_NOT_CHEATING
            elif error_message.find(b'UNKNOWN_ERROR')!=-1:
                return ERROR_NOT_UNKNOWN
            else:
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
        received_flag=recvMessage(team_socket)
        if received_flag[:len(flag)]!=flag:
            return ERROR_WRONG_FLAG
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            return ERROR_NOT_EXITING_PROOF
        sendMessage(team_socket,b'exit')

        if recvMessage(team_socket)!=b'GOODBYE':
            return ERROR_NOT_EXITING
        """
        

    except ConnectionResetError:
        return ERROR_CONNECTION_RESET


if __name__=="__main__":
    while True:
        #time.sleep(0.1)
        result=check_team_server(TEAM_HOST,TEAM_PORT)
        print (result)
        if result==1:
        
            break

