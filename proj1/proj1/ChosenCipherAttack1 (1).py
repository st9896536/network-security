# -*- coding: utf-8 -*-
"""
Created on Fri Mar  9 12:56:25 2018

@author: user
"""

from Crypto.PublicKey import RSA
import math
from fractions import gcd
from random import randint
import base64
import socket
import binascii


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


if __name__ == '__main__' :
    

    fileOfKey = open("pub.pem", "rb")
    key = RSA.importKey(fileOfKey.read())
    n = key.n
    e = key.e
    print ('n:',key.n) #displays n
    print()
    print ('e:',key.e) #displays e


    
#find X ralative prime number to n
    X = 137
    
    '''
    X=randint(1,9999)
    while(math.gcd(n,X) != 1):
        X=randint(1,9999)
        continue
    '''
#Creat Y = C*X**e mod n  
        
    fileOfFlag = open("flag.enc", "r")
    flag = fileOfFlag.read().strip()
    
    flag = base64.b64decode(flag)
    
    
    # Use binascii.hexlify to transfer byte string into integer
    #C = int(binascii.hexlify(bytes(flag,'utf-8')),16)
    C = int(binascii.hexlify(flag),16)
    Y =C * (X**e) % n
    
    # use binascii.unhexlify to transfer integer into byte string
    Y= binascii.unhexlify(hex(Y)[2:])
    
    
    temp = base64.b64encode(Y)
    
    temp = str(temp)[2:-1]+'\n'
    

    #Connect to server to decrypt
    host = "140.113.194.66"
    port = 8888
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    data = s.recv(1024)
    print(data.decode("utf-8") )
    #temp = s.sendall(bytes(temp+'\n',"utf-8"))
    s.sendall(bytes(temp,"utf-8"))
    data = s.recv(9999)
    print(data.decode("utf-8") )
    
    data = s.recv(9999)
    print(data.decode("utf-8") )
    
    data = data.strip()
    
    data2 = base64.b64decode(data)
    
    Z = int(binascii.hexlify(data2), 16)
    
    XInverse = modinv(X , n)
    P = Z * XInverse % n
    print(P)
    
    print(binascii.unhexlify(hex(P)[2:]).decode("utf-8"))
    
    #.decode('iso-8859-9'))
    
#.decode('mac-roman'

    
    

    

        
        
        
