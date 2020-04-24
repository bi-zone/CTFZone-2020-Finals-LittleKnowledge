#!/usr/bin/python3
try:
    from .zkn_support import * 
except (ModuleNotFoundError,ImportError):
    from zkn_support import *
import socket
import random
import os
import time
from datetime import datetime
private_key="""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7Ke0XHgzkBlvR1ZWyQIKtAB8uJyASo86hOGRSYJHGrI4WZVA
GV3D/hXf5x5DXmL21NyiVeg7W+cqSB4KBp2zDH7CcLWDpMKv/SmgyWbZizCRqqvs
4AebbQ3ACCYfRfGx3xX0o6MAuwWtyg+ChoL72DOg0+7wu4BvG/R36US6KsYjMftD
yr9BrxoRHuxVHs6/yMg7tNYnB66PE2Vw9vggG9wu9rVLK5c1w9tmVMUjqYJ+yASG
q2IFkUZirTmhUxkNKmlCHt1jpz2fhW9L3U4Uvwj1mw3htExn3SUPQQihdnIM0S4B
wSW38/PRlUulUmxHlM9bj8m2sizfrsqkq8Xw5QIBAwKCAQEAncUi6FAiYBD02jmP
MKwHIqr90GhVhwonA0ELhlbaEcwlkQ4qu5PX/rk/72mCPuykjehsOUV85+9xhWlc
BGkiCFSBoHkCbdcf/hvAhkSRB3W2ccfzQAUSSLPVWsQU2UvL6g6jF8IAfK5z3ApX
BFdSkCJrN/SgfQBKEqL6m4Mmxy158Vq0lzMb/itRlTWAZ0nANXMV029MAthT2Y2O
R+GWFfd+gXgTu15adqwzweoqn1CKidAtBxpLQiHoXAx3n4rIRLADBPvCWx9bcIA2
c1bXPwQlYHk/dKrIf0Z416KjlGAsgNFKZvSbGyII2/InUn2xunCIc7lgL+wueKdB
HHoPswKBgQD3WLzsbpxurUfhy5ldA65vaGpHDpYrrANF/5pvrrCmdhFd1D8jPi+u
D+GrAopewubLpU3UQsovrM9jaUdLCP3sJ9hy/Jozg4m2azOMoPT+swHtrg9o2y+X
o5MBn190mqYl2BgFpbkRsEHbm9k/XvS+Jy4smWzBo0cOiw0+DyMNqwKBgQD07zZI
eVYpBJE084K3gDGwEDFT6RkJV2bLTXar3HUYhNeTYEIKVFoAAfdtr1uE96LjU/5u
3fBlAUQiud+i2sr0m4jKmsmMmwTf8Xttj1bTLYDP3EiZqhyjeqhYXjU3fTukN9wM
gP29mv7or4cq97r+1fhiSMbkxwOLbsKE8evLrwKBgQCk5dNISb2fHi/r3RDorR70
8EbaCblycqzZVRGfycsZpAuT4tTCKXUetUEcrFw/LJndGN6NgdwfyIpCRi+HW1Py
xTr3UxF3rQZ5nM0Ia03/IgFJHrTwkh+6bQyrv5T4ZxlukBADw9C2dYE9EpDU6fh+
xMlzEPMrwi9fB14pX2yzxwKBgQCjSiQwUOQbWGDN96x6VXZ1YCDim2YGOkSHiPnH
6E4QWI+3lYFcODwAAU+edOet+myXjVRJ6UruANgXJpUXPIdNvQXcZzEIZ1iVS6ee
X483c6s1PYW7xr3CUcWQPs4k/ifCz+gIVf5+Z1SbH69x+nyp4/rsMISYhK0HnyxY
oUfdHwKBgGpu+4NO9n641DBz0bRigxOLen7mY4xU6R9aBMn2lkPsV1fsUWK82tt6
yFHerbz9OMSlapV9IayO7QMhVyRgSbtVhgwhTBoPwEe6OAQWAgs6/3iWEEozxiJm
0zFuVYywItI0mFbcJ8EYw6RWTX5ITI0YYvmhNMF2m2azfzftCMOC
-----END RSA PRIVATE KEY-----"""
(TEAM_HOST,TEAM_PORT)=('127.0.0.1',1337)

SUCCESS=0
ERROR_CONNECTION_REFUSED=1
ERROR_CONNECTION_RESET=2


ERROR_COULDNT_START_UPDATE=11
ERROR_DIDNT_RECEIVE_INITIAL_SETTINGS=41
ERROR_BAD_INTIAL_SETTINGS=12

ERROR_WITH_GRAPH_CREATION=13
ERROR_SENDING_GRAPH_SET_PACKET=42
ERROR_WITH_FINISHING_UPDATE=14

ERROR_COULDNT_START_PROTOCOL=15
ERROR_RECEIVING_PROOF_CONFIGURATION=16
ERRONEOUS_PROOF_CONFIGURATION=17
ERROR_COULDNT_CREATE_PROOFS=18
ERROR_COULDNT_CREATE_COMMITMENT_PACKET=19
ERROR_COULDNT_SAVE_COMMITMENT=20
ERROR_COULDNT_CREATE_CHALLENGE=21
ERROR_BAD_CHALLENGE=22
ERROR_SENDING_OR_GETTING_REVEAL=42
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

ERROR_SUCCESSFUL_WHEN_ERROR_INTENDED=50

def error_disambiguation(error_code):
    if error_code==SUCCESS:
        return "Everything went fine"
    elif error_code==ERROR_CONNECTION_REFUSED:
        return "Couldn't connect to team server"
    elif error_code==ERROR_COULDNT_START_UPDATE:
        return "Couldn't start flag and matrix update"
    elif error_code==ERROR_DIDNT_RECEIVE_INITIAL_SETTINGS:
        return "Didn't receive initial settings from team server"
    elif error_code==ERROR_BAD_INTIAL_SETTINGS:
        return "The initial settings packet is either malformed or contains unsupported values"
    elif error_code==ERROR_WITH_GRAPH_CREATION:
        return "This shouldn't happen. Contact task administrator (Graph Creation Error)"
    elif error_code==ERROR_SENDING_GRAPH_SET_PACKET:
        return "Connection dropped while sending graph set packet"
    elif error_code==ERROR_WITH_FINISHING_UPDATE:
        return "Didn't receive graph and flag update confirmation"
    elif error_code==ERROR_COULDNT_START_PROTOCOL:
        return "Couldn't start zero knowledge protocol"
    elif error_code==ERROR_RECEIVING_PROOF_CONFIGURATION:
        return "Problems with receiving proof configuration"
    elif error_code==ERRONEOUS_PROOF_CONFIGURATION:
        return "Proof configuration is wrong. You have probably been hacked"
    elif error_code==ERROR_COULDNT_CREATE_PROOFS:
        return "This shouldn't happen. Contact task administrator (Proof Creation Error)"
    elif error_code==ERROR_COULDNT_CREATE_COMMITMENT_PACKET:
        return "This shouldn't happen. Contact task administrator (Commitment Creation Error)"
    elif error_code==ERROR_COULDNT_SAVE_COMMITMENT:
        return "Couldn't save commitment"
    elif error_code==ERROR_COULDNT_CREATE_CHALLENGE:
        return "Couldn't create challenge"
    elif error_code==ERROR_BAD_CHALLENGE:
        return "Error in received challenge"
    elif error_code==ERROR_SENDING_OR_GETTING_REVEAL:
        return "Couldn't send reveal or get answer"
    elif error_code==ERROR_UNDEFINED_ON_CORRECT_PROOF:
        return "Received undefined error response to correct proof"
    elif error_code==ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF:
        return "Received system error response to correct proof"
    elif error_code==ERROR_NOT_PWN:
        return "Received pwning error response to correct proof"
    elif error_code==ERROR_NOT_EARLY:
        return "Received EARLY error response to correct proof"
    elif error_code==ERROR_NOT_CHEATING:
        return "Received cheating error response to correct proof"
    elif error_code==ERROR_NOT_UNKNOWN:
        return "Received unknown error response to correct proof"
    elif error_code==ERROR_WRONG_FLAG:
        return "Received wrong flag. You have probably been hacked"
    elif error_code==ERROR_SHOULD_BE_CHEATING_OR_PWNING:
        return "Received success when sending erroneous commitments or proofs"
    elif error_code==ERROR_NOT_EXITING_PROOF:
        return "Couldn't exit protocol"
    elif error_code==ERROR_NOT_EXITING:
        return "Couldn't exit connection"
    elif ERROR_SUCCESSFUL_WHEN_ERROR_INTENDED:
        return "Received success when sending erroneous commitments or proofs"
    else:
        return "Contact administrator. The strangest error of them all: "+str(error_code)

def is_success_return_code(return_code):
    return return_code==SUCCESS

def is_down_return_code(return_code):
    return return_code==ERROR_CONNECTION_REFUSED
def is_corrupt_return_code(return_code):
    if return_code==ERRONEOUS_PROOF_CONFIGURATION or return_code==ERROR_WRONG_FLAG:
        return True
    else:
        return False
def is_mumble_return_code(return_code):
    if is_success_return_code(return_code) or is_down_return_code(return_code) or is_corrupt_return_code(return_code):
        return False
    else:
        return True


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
        return os.urandom(random.randint(10,len(buffer)))


def push_flag(HOST,PORT,flag):
    global private_key
    prover=Prover(flag,private_key)
    flag_pushed=False
    next_stage=-1
    storedFN=None
    try:
        next_stage=ERROR_CONNECTION_REFUSED 
        team_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        team_socket.settimeout(3)
        try:
            team_socket.connect((HOST,PORT))
        except (ConnectionRefusedError,socket.timeout):
            team_socket.close()
            return (ERROR_CONNECTION_REFUSED,storedFN)
        next_stage=ERROR_COULDNT_START_UPDATE
        sendMessage(team_socket,"update_graph")
        if recvMessage(team_socket)!=b'STARTING_UPDATE':
            team_socket.close()
            return (ERROR_COULDNT_START_UPDATE,storedFN)
        next_stage=ERROR_DIDNT_RECEIVE_INITIAL_SETTINGS
        initial_settings=recvMessage(team_socket)
        if not prover.createFullKnowledge(initial_settings):
            team_socket.close()
            return (ERROR_BAD_INTIAL_SETTINGS,storedFN)
        storedFN=prover.packFullKnowledge()
        prover=Prover.restoreFromStorage(flag,private_key,storedFN)
        (graphSetPacket, signature)=prover.createGraphSetPacketAndHash(initial_settings)
        if (graphSetPacket)==None:
            team_socket.close()
            return (ERROR_WITH_GRAPH_CREATION,storedFN)
        next_stage=ERROR_SENDING_GRAPH_SET_PACKET
        sendMessage(team_socket,graphSetPacket)
        sendMessage(team_socket,signature)
        next_stage=ERROR_WITH_FINISHING_UPDATE
        result=recvMessage(team_socket)
        if result!=b'SUCCESS':
            team_socket.close()
            return (ERROR_WITH_FINISHING_UPDATE,storedFN)
        flag_pushed=True
        sendMessage(team_socket,b'exit')

        if recvMessage(team_socket)!=b'GOODBYE':
            team_socket.close()
            return (SUCCESS,storedFN)
        team_socket.close()
        return (SUCCESS,storedFN)
    except (TooMuchData, NotEnoughData,ConnectionAbortedError,ConnectionResetError, socket.timeout,OSError) as e:
        try:
            team_socket.close()
        except OSError:
            pass
        if flag_pushed:
            return (SUCCESS,storedFN)
        else:
            return (next_stage,storedFN)



def pull_flag(HOST,PORT,flag,storedFullKnowledge):
    global private_key
    if isinstance(flag,str):
        flag=flag.encode()
    prover=Prover.restoreFromStorage(flag,private_key,storedFullKnowledge)
    flag_received=False
    try:
        next_stage=ERROR_CONNECTION_REFUSED
        team_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        team_socket.settimeout(3)
        try:
            team_socket.connect((HOST,PORT))
        except (ConnectionRefusedError,socket.timeout):
            team_socket.close()
            return ERROR_CONNECTION_REFUSED
        next_stage=ERROR_COULDNT_START_PROTOCOL
        
        sendMessage(team_socket,b'start_zkn_protocol')
        if recvMessage(team_socket)!=b'STARTING_PROTOCOL':
            team_socket.close()
            return ERROR_COULDNT_START_PROTOCOL
        next_stage=ERROR_RECEIVING_PROOF_CONFIGURATION
        sendMessage(team_socket,b'get_configuration')
        proof_configuration=recvMessage(team_socket)
        if (proof_configuration==b'ERROR'):
            team_socket.close()
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            team_socket.close()
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            team_socket.close()
            return ERROR_COULDNT_CREATE_PROOFS
        commitment_packet=prover.createCommitmentPacket()
        if commitment_packet==None:
            team_socket.close()
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET
        next_stage=ERROR_COULDNT_SAVE_COMMITMENT
        sendMessage(team_socket,b'save_commitment')
        sendMessage(team_socket,commitment_packet)
        if recvMessage(team_socket)!=b'SUCCESS':
            team_socket.close()
            return ERROR_COULDNT_SAVE_COMMITMENT
        
        next_stage=ERROR_COULDNT_CREATE_CHALLENGE
        sendMessage(team_socket,b'create_challenge')
        
        challenge=recvMessage(team_socket)
        if challenge==b'ERROR':
            team_socket.close()
            return ERROR_COULDNT_CREATE_CHALLENGE
        revealPacket=prover.createRevealPacket(challenge)
        if revealPacket==None:
            team_socket.close()
            return ERROR_BAD_CHALLENGE
        next_stage=ERROR_SENDING_OR_GETTING_REVEAL 
        sendMessage(team_socket,b'check_proof')
        sendMessage(team_socket,revealPacket)
        check_proof_result=recvMessage(team_socket)
        if check_proof_result!=b'SUCCESS':
            if check_proof_result!=b'ERROR':
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
            error_message=recvMessage(team_socket)
            if error_message.find(b'SYSTEM_ERROR')!=-1:
                team_socket.close()
                return ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF
            elif error_message.find(b'PWN_ATTEMPT_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_PWN
            elif error_message.find(b'TOO_EARLY')!=-1:
                team_socket.close()
                return ERROR_NOT_EARLY
            elif error_message.find(b'CHEATING_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_CHEATING
            elif error_message.find(b'UNKNOWN_ERROR')!=-1:
                team_socket.close()
                return ERROR_NOT_UNKNOWN
            else:
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
        received_flag=recvMessage(team_socket)

        if received_flag[:len(flag)]!=flag:
            team_socket.close()
            return ERROR_WRONG_FLAG
        flag_received=True
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            team_socket.close()
            return ERROR_NOT_EXITING_PROOF
        sendMessage(team_socket,b'exit')

        if recvMessage(team_socket)!=b'GOODBYE':
            team_socket.close()
            return ERROR_NOT_EXITING
        team_socket.close()
        return SUCCESS
    except (TooMuchData, NotEnoughData,ConnectionAbortedError,ConnectionResetError,socket.timeout,OSError) as e:
        try:
            team_socket.close()
        except OSError:
            pass
        if flag_received:
            return SUCCESS
        else:
            return next_stage


def multiple_challenges_before_pull(HOST,PORT,flag,storedFullKnowledge):
    global private_key
    if isinstance(flag,str):
        flag=flag.encode()
    prover=Prover.restoreFromStorage(flag,private_key,storedFullKnowledge)
    flag_received=False
    try:
        next_stage=ERROR_CONNECTION_REFUSED
        team_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        team_socket.settimeout(3)
        try:
            team_socket.connect((HOST,PORT))
        except (ConnectionRefusedError,socket.timeout):
            team_socket.close()
            return ERROR_CONNECTION_REFUSED
        next_stage=ERROR_COULDNT_START_PROTOCOL

        starting_time=datetime.now() 
        
        sendMessage(team_socket,b'start_zkn_protocol')
        if recvMessage(team_socket)!=b'STARTING_PROTOCOL':
            team_socket.close()
            return ERROR_COULDNT_START_PROTOCOL
        next_stage=ERROR_RECEIVING_PROOF_CONFIGURATION
        sendMessage(team_socket,b'get_configuration')
        proof_configuration=recvMessage(team_socket)
        if (proof_configuration==b'ERROR'):
            team_socket.close()
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            team_socket.close()
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            team_socket.close()
            return ERROR_COULDNT_CREATE_PROOFS
        commitment_packet=prover.createCommitmentPacket()
        if commitment_packet==None:
            team_socket.close()
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET
        next_stage=ERROR_COULDNT_SAVE_COMMITMENT
        sendMessage(team_socket,b'save_commitment')
        
        
        sendMessage(team_socket,commitment_packet)
        

        if recvMessage(team_socket)!=b'SUCCESS':
            team_socket.close()
            return ERROR_COULDNT_SAVE_COMMITMENT
        next_stage=ERROR_COULDNT_CREATE_CHALLENGE
        count=0
        while (datetime.now()-starting_time).seconds<10:

            sendMessage(team_socket,b'create_challenge')
        
            challenge=recvMessage(team_socket)
            count+=1
            if challenge==b'ERROR':
                team_socket.close()
                return ERROR_COULDNT_CREATE_CHALLENGE
    
        revealPacket=prover.createRevealPacket(challenge)
        if revealPacket==None:
            team_socket.close()
            return ERROR_BAD_CHALLENGE
        next_stage=ERROR_SENDING_OR_GETTING_REVEAL 
        sendMessage(team_socket,b'check_proof')
        sendMessage(team_socket,revealPacket)
        check_proof_result=recvMessage(team_socket)
        if check_proof_result!=b'SUCCESS':
            if check_proof_result!=b'ERROR':
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
            error_message=recvMessage(team_socket)
            if error_message.find(b'SYSTEM_ERROR')!=-1:
                team_socket.close()
                return ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF
            elif error_message.find(b'PWN_ATTEMPT_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_PWN
            elif error_message.find(b'TOO_EARLY')!=-1:
                team_socket.close()
                return ERROR_NOT_EARLY
            elif error_message.find(b'CHEATING_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_CHEATING
            elif error_message.find(b'UNKNOWN_ERROR')!=-1:
                team_socket.close()
                return ERROR_NOT_UNKNOWN
            else:
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
        received_flag=recvMessage(team_socket)

        if received_flag[:len(flag)]!=flag:
            team_socket.close()
            return ERROR_WRONG_FLAG
        flag_received=True
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            team_socket.close()
            return ERROR_NOT_EXITING_PROOF
        
        sendMessage(team_socket,b'exit')
        if recvMessage(team_socket)!=b'GOODBYE':
            team_socket.close()
            return ERROR_NOT_EXITING
        team_socket.close()
        return SUCCESS
    except (TooMuchData, NotEnoughData,ConnectionAbortedError,ConnectionResetError,socket.timeout,OSError) as e:
        try:
            team_socket.close()
        except OSError:
            pass
        if flag_received:
            return SUCCESS
        else:
            return next_stage

def bad_commitments_or_proofs(HOST,PORT,flag,storedFullKnowledge):
    global private_key
    if isinstance(flag,str):
        flag=flag.encode()
    prover=Prover.restoreFromStorage(flag,private_key,storedFullKnowledge)
    flag_received=False
    try:
        next_stage=ERROR_CONNECTION_REFUSED
        team_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        team_socket.settimeout(3)
        try:
            team_socket.connect((HOST,PORT))
        except (ConnectionRefusedError,socket.timeout):
            team_socket.close()
            return ERROR_CONNECTION_REFUSED
        next_stage=ERROR_COULDNT_START_PROTOCOL

        starting_time=datetime.now() 
        
        sendMessage(team_socket,b'start_zkn_protocol')
        if recvMessage(team_socket)!=b'STARTING_PROTOCOL':
            team_socket.close()
            return ERROR_COULDNT_START_PROTOCOL
        next_stage=ERROR_RECEIVING_PROOF_CONFIGURATION
        sendMessage(team_socket,b'get_configuration')
        proof_configuration=recvMessage(team_socket)
        if (proof_configuration==b'ERROR'):
            team_socket.close()
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            team_socket.close()
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            team_socket.close()
            return ERROR_COULDNT_CREATE_PROOFS
        good_commitment_packet=prover.createCommitmentPacket()
        if good_commitment_packet==None:
            team_socket.close()
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET
        count=0
        while (datetime.now()-starting_time).seconds<12:
            count+=1
            next_stage=ERROR_COULDNT_SAVE_COMMITMENT
            whatToBreak=random.randint(0,1)
            if whatToBreak==0:
                commitment_packet=malform_buffer(good_commitment_packet)
                while len(commitment_packet)<8:
                    commitment_packet=malform_buffer(good_commitment_packet)
            else:
                commitment_packet=good_commitment_packet
            sendMessage(team_socket,b'save_commitment')
            sendMessage(team_socket,commitment_packet)
            if recvMessage(team_socket)!=b'SUCCESS':
                team_socket.close()
                return ERROR_COULDNT_SAVE_COMMITMENT
            next_stage=ERROR_COULDNT_CREATE_CHALLENGE

            sendMessage(team_socket,b'create_challenge')
        
            challenge=recvMessage(team_socket)
            if challenge==b'ERROR':
                team_socket.close()
                return ERROR_COULDNT_CREATE_CHALLENGE
        
            revealPacket=prover.createRevealPacket(challenge)
            if (whatToBreak==1):
                revealPacket=malform_buffer(revealPacket)
            
            if revealPacket==None:
                team_socket.close()
                return ERROR_BAD_CHALLENGE
            next_stage=ERROR_SENDING_OR_GETTING_REVEAL 
            sendMessage(team_socket,b'check_proof')
            sendMessage(team_socket,revealPacket)
            check_proof_result=recvMessage(team_socket)
            if check_proof_result==b'SUCCESS':
                team_socket.close()
                return ERROR_SUCCESSFUL_WHEN_ERROR_INTENDED 
            recvMessage(team_socket)
        next_stage=ERROR_COULDNT_SAVE_COMMITMENT
        sendMessage(team_socket,b'save_commitment')
        sendMessage(team_socket,good_commitment_packet)
        if recvMessage(team_socket)!=b'SUCCESS':
            team_socket.close()
            return ERROR_COULDNT_SAVE_COMMITMENT
        
        next_stage=ERROR_COULDNT_CREATE_CHALLENGE
        sendMessage(team_socket,b'create_challenge')
        
        challenge=recvMessage(team_socket)
        if challenge==b'ERROR':
            team_socket.close()
            return ERROR_COULDNT_CREATE_CHALLENGE
        revealPacket=prover.createRevealPacket(challenge)
        if revealPacket==None:
            team_socket.close()
            return ERROR_BAD_CHALLENGE
        next_stage=ERROR_SENDING_OR_GETTING_REVEAL 
        sendMessage(team_socket,b'check_proof')
        sendMessage(team_socket,revealPacket)
        check_proof_result=recvMessage(team_socket)
        if check_proof_result!=b'SUCCESS':
            if check_proof_result!=b'ERROR':
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF
            error_message=recvMessage(team_socket)
            if error_message.find(b'SYSTEM_ERROR')!=-1:
                team_socket.close()
                return ERROR_SYSTEM_ON_VERIFIER_DURING_PROOF
            elif error_message.find(b'PWN_ATTEMPT_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_PWN
            elif error_message.find(b'TOO_EARLY')!=-1:
                team_socket.close()
                return ERROR_NOT_EARLY
            elif error_message.find(b'CHEATING_DETECTED')!=-1:
                team_socket.close()
                return ERROR_NOT_CHEATING
            elif error_message.find(b'UNKNOWN_ERROR')!=-1:
                team_socket.close()
                return ERROR_NOT_UNKNOWN
            else:
                team_socket.close()
                return ERROR_UNDEFINED_ON_CORRECT_PROOF

        received_flag=recvMessage(team_socket)

        if received_flag[:len(flag)]!=flag:
            team_socket.close()
            return ERROR_WRONG_FLAG
        flag_received=True
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            team_socket.close()
            return ERROR_NOT_EXITING_PROOF
        return SUCCESS
    except (TooMuchData, NotEnoughData,ConnectionAbortedError,ConnectionResetError,socket.timeout,OSError) as e:
        try:
            team_socket.close()
        except OSError:
            pass
        if flag_received:
            return SUCCESS
        else:
            return next_stage


def complex_pull_flag(HOST,PORT,flag,storedFullKnowledge):
    chosen=random.randint(0,2)
    if chosen==0:
        return pull_flag(HOST,PORT,flag,storedFullKnowledge)
    elif chosen==1:
        return multiple_challenges_before_pull(HOST,PORT,flag,storedFullKnowledge)
    else:
        return bad_commitments_or_proofs(HOST,PORT,flag,storedFullKnowledge)

if __name__=="__main__":
    while True:
        #time.sleep(0.3)
        #time.sleep(1)
        a=datetime.now()
        (resulting_status,storedFullKnowledge)=push_flag(TEAM_HOST,TEAM_PORT,b'TEST_FLAG')
        print ('Result of initial check:',error_disambiguation(resulting_status))
        #time.sleep(0.5)
        resulting_status=complex_pull_flag(TEAM_HOST,TEAM_PORT,b'TEST_FLAG',storedFullKnowledge)
        print('Result of additional check:',error_disambiguation(resulting_status))

        b=datetime.now()

        print ('Time delta:',(b-a).microseconds)