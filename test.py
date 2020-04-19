#!/usr/bin/python3
from support import *
v=Verifier(8,8,7)
initialSetting=v.getInitialSettingPacket()
print(initialSetting)
p=Prover(b'FLAG',b'KEY')
p.createFullKnowledge(initialSetting)
cur_res=p.createGraphSetPacketAndHash(initialSetting)
if cur_res==None:
    exit()
(graphSetPacket,signature)=cur_res
print(v.updateFullKnowledge(graphSetPacket,signature))
prV=ZKNProtocolVerifier(v)
configurationPacket=prV.createProofConfigurationPacket()
print(configurationPacket)
p.initializeProofHelper(configurationPacket)
p.createProofs()
commitment=p.createCommitmentPacket()
print (commitment)
prV.saveCommitment(commitment)
challenge=prV.createChallenge()
print(challenge)
reveal=p.createRevealPacket(challenge)
print(reveal)