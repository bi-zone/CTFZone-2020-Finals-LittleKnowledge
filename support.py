#!/usr/bin/python3
from ctypes import *
import struct
import os
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
ZKNLIBRARY_NAME='./libzkn.so'
FLAG_ARRAY_SIZE=2048
class TooMuchData(Exception):
    pass
class NotEnoughData(Exception):
    pass
def recvMessage(socket):
    size_bytes=b''
    while len(size_bytes)!=4:
        r=socket.recv(4-len(size_bytes))
        if r==b'':
            raise NotEnoughData
        size_bytes+=r
    size=struct.unpack('<I',size_bytes)[0]
    if size>0x400000:
        raise TooMuchData
    data=b''
    size_left=size
    while size_left>0:
        if size_left<1024:
            new_chunk=socket.recv(size_left)
        else:
            new_chunk=socket.recv(1024)
        if new_chunk==b'':
            raise NotEnoughData
        data+=new_chunk
        size_left-=len(new_chunk)
    return data

def sendMessage(socket,data):
    if (isinstance(data,str)):
        data=data.encode()
    size=len(data)
    socket.sendall(struct.pack('<I',size)+data)

class ZKnLibNotFound(Exception):pass
class ZKnLibNotALib(Exception):pass
class ZKnStateNotCreated(Exception):pass
class PrivateKeyCantBeParsed(Exception):pass
class Prover:
    def __init__(self, flag,raw_key):
        if isinstance(flag,str):
            flag=flag.encode()
        if len(flag)<FLAG_ARRAY_SIZE:
            flag=flag+b'\x00'*(FLAG_ARRAY_SIZE-len(flag))
        self.flag=flag
        if not os.path.isfile(ZKNLIBRARY_NAME):
            raise ZKnLibNotFound
        try:
            self.key=RSA.import_key(raw_key)
        except (ValueError, IndexError, TypeError) as e:
            raise PrivateKeyCantBeParsed
        self.key_size=self.key.size_in_bytes()
        try:
            self.zknlib=cdll.LoadLibrary(ZKNLIBRARY_NAME)
        except OSError:
            raise ZKnLibNotALib
        self.full_knowledge=None
        self.proof_helper=None
        self.proofs_for_one_round=None
        self.extra_information=None
    def createFullKnowledge(self, initialSettingsPacket):
        insetBytesP=create_string_buffer(initialSettingsPacket,len(initialSettingsPacket))
        self.zknlib.getDesiredVerticeCountFromInitialSettingPacket.restype=c_uint16
        verticeCount=self.zknlib.getDesiredVerticeCountFromInitialSettingPacket(insetBytesP,c_uint32(len(initialSettingsPacket)))
        self.zknlib.createFullKnowledgeForServer.restype=c_void_p
        result=self.zknlib.createFullKnowledgeForServer(verticeCount)
        self.full_knowledge=cast(result,POINTER(c_uint8))
        if result==None:
            return False
        else:
            return True
        
    def createGraphSetPacketAndHash(self, initialSettingsPacket):
        self.zknlib.createGraphSetPacket.restype=c_void_p
        insetBytesp=create_string_buffer(initialSettingsPacket,len(initialSettingsPacket))
        flagBytesP=create_string_buffer(self.flag,FLAG_ARRAY_SIZE)
        outputPacketSize=c_uint32(0)
        graphSetPacket=self.zknlib.createGraphSetPacket(self.full_knowledge,insetBytesp,flagBytesP,pointer(outputPacketSize))
        if graphSetPacket==None:
            return None
        graphSetPacket=cast(graphSetPacket,POINTER(c_uint8*outputPacketSize.value))
        ret_result= bytes(graphSetPacket.contents)
        self.zknlib.createPKCSSignature.restype=c_void_p
        signature=self.zknlib.createPKCSSignature(graphSetPacket,outputPacketSize,c_uint32(self.key_size))
        if (signature==None):
            self.zknlib.freeDanglingPointer(cast(graphSetPacket,POINTER(c_uint8)))
            return None
        singature_bytes_pt=bytes(cast(signature,POINTER(c_uint8*self.key_size)).contents)
        signature_final=long_to_bytes(pow(bytes_to_long(singature_bytes_pt),self.key.d,self.key.n),self.key_size)
        self.zknlib.freeDanglingPointer(cast(graphSetPacket,POINTER(c_uint8)))
        self.zknlib.freeDanglingPointer(cast(signature,POINTER(c_uint8)))
        return (ret_result,signature_final)
    
    
    def initializeProofHelper(self,proofConfiguration):
        pProofConfiguration=create_string_buffer(proofConfiguration,len(proofConfiguration))
        errorReason=c_uint8(0)
        self.zknlib.initializeProofHelper.restype=c_void_p
        result=self.zknlib.initializeProofHelper(self.full_knowledge,pProofConfiguration,c_uint32(len(proofConfiguration)),pointer(errorReason))
        self.proof_helper=cast(result,POINTER(c_uint8))
        if result==None:
            return False
        else:
            return True

    def createProofs(self):
        self.zknlib.createProofsForOneRound.restype=c_void_p
        result=self.zknlib.createProofsForOneRound(self.proof_helper)
        self.proofs_for_one_round=cast(result,POINTER(c_uint8))
        if result==None:
            return False
        else:
            return True
    def createCommitmentPacket(self):
        outputPacketSize=c_uint32(0)
        outputExtraInformation=POINTER(POINTER(c_ubyte))()
        self.zknlib.createCommitmentPacket.restype=c_void_p
        result_raw=self.zknlib.createCommitmentPacket(self.proofs_for_one_round,self.proof_helper,pointer(outputPacketSize),pointer(outputExtraInformation))
        if result_raw==None:
            return None
        result_bytes=bytes(cast(result_raw,POINTER(c_uint8*outputPacketSize.value)).contents)
        self.extra_information=cast(outputExtraInformation,POINTER(c_uint8))
        self.zknlib.freeDanglingPointer(cast(result_raw,POINTER(c_uint8)))
        return result_bytes

    def createRevealPacket(self,challenge):
        pChallenge=create_string_buffer(challenge,len(challenge))
        outputPacketSize=c_uint32(0)
        self.zknlib.createRevealPacket.restype=c_void_p
        result_raw=self.zknlib.createRevealPacket(self.proofs_for_one_round,self.proof_helper,pChallenge,self.extra_information,pointer(outputPacketSize))
        if result_raw==None:
            return None
        result_bytes=bytes(cast(result_raw,POINTER(c_uint8*outputPacketSize.value)).contents)
        self.zknlib.freeDanglingPointer(cast(result_raw,POINTER(c_uint8)))
        return result_bytes


    def __del__(self):
        self.zknlib.freeFullKnowledgeForServer(self.full_knowledge)
        self.zknlib.freeProofsForOneRound(self.proofs_for_one_round,self.proof_helper)
        self.zknlib.freeCommitmentExtraInformation(self.proof_helper,self.extra_information)
        self.zknlib.freeProofHelper(self.proof_helper)
        
class PublicKeyNotFound(Exception):pass
class PublicKeyParseError(Exception):pass
PUBLIC_KEY_FILE_NAME="public.pem"
class Verifier:
    def __init__(self,verticeCount,checkCount,supportedAlgorithms):
        if not os.path.isfile(ZKNLIBRARY_NAME):
            raise ZKnLibNotFound
        if not os.path.isfile(PUBLIC_KEY_FILE_NAME):
            raise PublicKeyNotFound
        try:
            with open(PUBLIC_KEY_FILE_NAME,'r') as f:
                key_pem=f.read()
        except UnicodeDecodeError:
            raise PublicKeyParseError
        try:
            self.key=RSA.import_key(key_pem)
        except (ValueError,IndexError,TypeError) as e:
            raise PublicKeyParseError
        try:
            self.zknlib=cdll.LoadLibrary(ZKNLIBRARY_NAME)
            self.zknlib.initializeZKnState.restype=c_void_p
            result=self.zknlib.initializeZKnState(c_uint16(verticeCount),c_uint8(checkCount),c_uint8(supportedAlgorithms))
            self.ZKnState=cast(result,POINTER(c_uint8))
            if (result==None): raise ZKnStateNotCreated("Couldn't create ZKnState (probably bad parameters)")
        except OSError as e:
            #print (e)
            raise ZKnLibNotALib
    def getInitialSettingPacket(self):
        self.zknlib.createInitialSettingPacket.restype=c_void_p

        p=self.zknlib.createInitialSettingPacket(cast(self.ZKnState,POINTER(c_uint8)))
        if p==None:
            return None
        result=bytes(cast(p,POINTER(c_uint8*18)).contents)
        self.zknlib.freeDanglingPointer(cast(p,POINTER(c_uint8)))
        self.last_random_r=result
        return result
    
    def updateZKnGraph(self,graphSetPacket,signature):
        if len(signature)!=self.key.size_in_bytes():
            return False
        encrypted_signature=long_to_bytes(pow(bytes_to_long(signature),self.key.e,self.key.n),self.key.size_in_bytes())
        self.zknlib.updateZKnGraph.restype=c_uint32

        pGraphSetPacket=create_string_buffer(graphSetPacket,len(graphSetPacket))
        pSignature=create_string_buffer(encrypted_signature,len(encrypted_signature))
        pRANDOMR=create_string_buffer(self.last_random_r,len(self.last_random_r))
        result=self.zknlib.updateZKnGraph(self.ZKnState,pGraphSetPacket,c_uint32(len(graphSetPacket)),pSignature,c_uint32(len(signature)),pRANDOMR)
        return result==0
    
    def __del__(self):
        self.zknlib.destroyZKnState(self.ZKnState)

class NotVerifier(Exception):pass

class ZKNProtocolVerifier:
    def __init__(self,verifier):
        if not isinstance(verifier,Verifier):
            raise NotVerifier
        self.zknlib=verifier.zknlib
        self.verifier=verifier
        self.zknlib.initializeZKnProtocolState.restype=c_void_p
        self.ZKnProtocolState=cast(self.zknlib.initializeZKnProtocolState(),POINTER(c_uint8))

    def createProofConfigurationPacket(self):
        outputPacketSize=c_uint32(0)
        self.zknlib.createProofConfigurationPacket.restype=c_void_p
        raw_packet_original=self.zknlib.createProofConfigurationPacket(self.verifier.ZKnState,pointer(outputPacketSize))
        if (raw_packet_original==None):
            return None
        raw_packet=cast(raw_packet_original,POINTER(c_uint8*outputPacketSize.value))
        result=bytes(raw_packet.contents)
        self.zknlib.freeDanglingPointer(cast(raw_packet_original,POINTER(c_uint8)))
        return result

    def saveCommitment(self, commitment):
        pbCommitmentData=create_string_buffer(commitment,len(commitment))
        self.zknlib.saveCommitment.restype=c_uint8
        return self.zknlib.saveCommitment(self.verifier.ZKnState,self.ZKnProtocolState,pbCommitmentData,c_uint32(len(commitment)))

    def createChallenge(self):
        outputPacketSize=c_uint32(0)
        self.zknlib.createChallenge.restype=c_void_p
        result_raw=self.zknlib.createChallenge(self.verifier.ZKnState,self.ZKnProtocolState,pointer(outputPacketSize))
        if result_raw==None:
            return None
        result_bytes=bytes(cast(result_raw,POINTER(c_uint8*outputPacketSize.value)).contents)
        self.zknlib.freeDanglingPointer(cast(result_raw,POINTER(c_uint8)))
        return result_bytes
    
    def checkProof(self,revealPacket):
        pRevealPacket=create_string_buffer(revealPacket,len(revealPacket))
        pbFlag=cast(pointer(c_uint8(0)),POINTER(c_uint8*FLAG_ARRAY_SIZE))
        errorReason=c_uint8(0)
        self.zknlib.checkProof.restype=c_uint8
        result=self.zknlib.checkProof(self.verifier.ZKnState,self.ZKnProtocolState,pRevealPacket,len(revealPacket),pointer(pbFlag),pointer(errorReason))
        if result!=0:
            return (result,errorReason.value)
        else:
            return (result,bytes(pbFlag.contents))


    def __del__(self):
        self.zknlib.destroyZKnProtocolState(self.ZKnProtocolState)

