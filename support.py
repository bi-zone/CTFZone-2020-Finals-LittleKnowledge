#!/usr/bin/python3
import struct
class TooMuchData(Exception):
    pass
def recvMessage(socket):
    size_bytes=b''
    while len(size_bytes)!=4:
        size_bytes+=socket.recv(4-len(size_bytes))
    size=struct.unpack('<I',size_bytes)[0]
    if size>0x100000:
        raise TooMuchData
    data=b''
    size_left=size
    while size_left>0:
        if size_left<1024:
            new_chunk=socket.recv(size_left)
        else:
            new_chunk=socket.recv(1024)
        data+=new_chunk
        size_left-=len(new_chunk)
    return data

def sendMessage(socket,data):
    size=len(data)
    socket.sendall(struct.pack('<I',size)+data)

