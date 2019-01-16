#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 23 11:45:53 2018

@author: Rong
"""


import socket
import sys,os,signal
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto import Random
import binascii
import base64




# Extended Greatest Common Divisor
def egcd(a, b):
  if (a == 0):
  	return (b, 0, 1)
  else:
  	g, y, x = egcd(b % a, a)
  	return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
  g, x, y = egcd(a, m)
  if (g != 1):
  	raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
  else:
  	return x % m


# Get public key
def getpubkey():
    with open('./pub.pem','rb') as f:
        pub = f.read()
        public_key = RSA.importKey(pub)
        
        n = public_key.n  #140816102882370072753963128960517081965880280303822400235001309160195926187868730723645674960568062473761002103307583098926327676818048971808675637139699318767264291797993510624508457914745131902730458707154587694229291440822570657047495880598540768909211668263294445392516077874925310419418057302897080960859
        e = public_key.e  #65537

    return public_key,n,e

if __name__ == '__main__' :
    
    #alarm(60)
    #sys.stdout=os.fdopen(sys.stdin.fileno(),"wb",0)
    key,n,e = getpubkey()
    
    
    with open('./flag.enc','rb') as f:
        flag = f.read().strip() #type:bytes
        flag = base64.b64decode(flag)
    
        
    #str_flag = str(flag, encoding = 'utf-8') # bytes to str
    
    # Use binascii.hexlify to transfer byte string into integer
    #flag_enc = int(binascii.hexlify(bytes(flag,'utf-8')),16)
    flag_enc = int(binascii.hexlify(flag),16)
    
    #choose X where X is relatively prime to n
    X = 997
    
    Y = flag_enc * (X ** e) % n
    
    # use binascii.unhexlify to transfer integer into byte string
    Y = binascii.unhexlify(hex(Y)[2:])
    
    Y = base64.b64encode(Y)
    
    Y = str(Y)[2:-1]+'\n'
    
    
    
    HOST = '140.113.194.66'
    PORT = 8888
    # create socket
    # AF_INET 代表使用標準 IPv4 位址或主機名稱
    # SOCK_STREAM 代表這會是一個 TCP client
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # client 建立連線
    sock.connect((HOST, PORT))
    
    # 接收資料
    response_enter = sock.recv(4096)   #接收4096字元
    print(response_enter.decode("utf-8"))
    
    # send encrypted message Y to server to decrypted
    sock.send(bytes(Y,"utf-8"))  #傳送Y出去
    response_receive = sock.recv(4096) 
    print(response_receive.decode("utf-8"))
    response_receive = sock.recv(4096)
    print(response_receive.decode("utf-8"))
    response_receive = response_receive.strip()
    
    
    
    response_receive = base64.b64decode(response_receive)
    
    # Use binascii.hexlify to transfer byte string into integer
    Z = int(binascii.hexlify(response_receive), 16)
    
    X_Inverse = modInv(X , n)
    P = (Z * X_Inverse) % n
    final_flag = binascii.unhexlify(hex(P)[2:])
    #print(str(final_flag, encoding = 'utf-8'))
    print(bytes.decode(final_flag))
