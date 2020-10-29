import sys
import socket
import fcntl
import struct
import array
import os
import select
import time
import signal
import sys

def ifconfig(max_possible=128):
  bytes = max_possible * 32
  names = array.array('B', b'\0' * bytes)
  names_memory_addr = names.buffer_info()[0]
  st = struct.pack('iL', bytes, names_memory_addr)
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s_fno = sock.fileno()
  outbytes = struct.unpack('iL',fcntl.ioctl(s_fno,0x8912,st))[0]
  lst = {}
  names_s = names.tobytes()
  for i in range(0,outbytes,40):
    name = names_s[i:i+16].split(b'\0',1)[0].decode()
    ip = '.'.join(map(str,names_s[i+20:i+24]))
    lst[name] = ip
  return lst

class Ping:

  @classmethod
  def _sock(cls):
    ICMP = socket.getprotobyname('icmp')
    sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,ICMP)
    return sock

  @classmethod
  def _checksum(cls,source):
    toIter = (int(len(source)/2))*2
    c_sum = 0
    Iterd = 0
    while Iterd < toIter:
      if (sys.byteorder == 'little'):
          A = source[Iterd]
          B = source[Iterd+1]
      else:
          A = source[Iterd+1]
          B = source[Iterd]
      c_sum = c_sum + (B*256 + A)
      Iterd += 2

    if toIter < len(source):
      A = source[len(source)-1]
      c_sum += A
    
    c_sum &= 0xffffffff
    c_sum = (c_sum >> 16) + (c_sum & 0xffff)
    c_sum+=(c_sum >> 16)
    answer = ~c_sum & 0xffff
    answer = socket.htons(answer)
    return answer

  @classmethod
  def _packet(cls,ID,seq):
    header = struct.pack('!BBHHH',8,0,0,ID,seq)
    padbytes = []
    for i in range(0x42,0x42+58):
      padbytes+=[(i&0xff)]
    data = bytearray(padbytes)
    chksum = cls._checksum(header+data)
    header = struct.pack('!BBHHH',8,0,chksum,ID,seq)
    packet = header + data
    return packet

  @classmethod
  def _recv(cls,sock,ID,timeout):
    s_time = time.time()
    while True:
      ready = select.select([sock],[],[],timeout)
      n_time = time.time()
      if ready[0] == []:
        return None
      retpkt,addr = sock.recvfrom(2048)
      kind,code,chksum,Id,seq = struct.unpack('!BBHHH',retpkt[20:28])
      if Id == ID:
        c_size = len(retpkt) -28
        return n_time - s_time
      timeout = n_time - s_time
      if timeout <= 0:
        return None
      
  @classmethod
  def send(cls,addr,count=1,timeout=1):
    if os.geteuid():
      raise Exception('ICMP packets may only be sent with root')
    ID = os.getpid() & 0xFFFF
    sock = cls._sock()
    for i in range(count):
      print('sending ping')
      sock.sendto(cls._packet(ID,i),(addr,1))
      print('received ping back in: ',cls._recv(sock,ID,timeout))
