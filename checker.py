#!/usr/bin/python3

from support import *
import socket
import random
import os
import time
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
    global private_key
    prover=Prover(flag,private_key)
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
        print (proof_configuration)
        if (proof_configuration==b'ERROR'):
            return ERROR_RECEIVING_PROOF_CONFIGURATION
        proof_helper_result=prover.initializeProofHelper(proof_configuration)
        if not proof_helper_result:
            return ERRONEOUS_PROOF_CONFIGURATION
        proofs_result=prover.createProofs()
        if not proofs_result:
            return ERROR_COULDNT_CREATE_PROOFS
        commitment_packet=prover.createCommitmentPacket()
        print ('Commitment packet length',len(commitment_packet))
        if commitment_packet==None:
            return ERROR_COULDNT_CREATE_COMMITMENT_PACKET
        sendMessage(team_socket,b'save_commitment')
        sendMessage(team_socket,commitment_packet)
        if recvMessage(team_socket)!=b'SUCCESS':
            return ERROR_COULDNT_SAVE_COMMITMENT
        
        sendMessage(team_socket,b'create_challenge')
        
        challenge=recvMessage(team_socket)
        print (challenge)
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
        print(len(received_flag))
        if received_flag[:len(flag)]!=flag:
            return ERROR_WRONG_FLAG
        sendMessage(team_socket,b"exit_protocol")
        received_answer=recvMessage(team_socket)
        if received_answer!=b'EXITING_PROOF':
            return ERROR_NOT_EXITING_PROOF
        #"""
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
        #"""
        

    except ConnectionResetError:
        return ERROR_CONNECTION_RESET


if __name__=="__main__":
    while True:
        #time.sleep(0.1)
        result=check_team_server(TEAM_HOST,TEAM_PORT)
        print (result)
        if result==1:
        
            break

