#!/usr/bin/env python2

from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
import sys,os,signal
import binascii




"""
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)
"""

"""
def alarm(time):
    def handler(signum, frame):
        print ('Timeout. Bye~')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(time)
"""


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

# Decrypt ciphertext using private key (PKCS1 OAEP format)
def do_decrypt(rsakey, ciphertext):
  rsakey = PKCS1_OAEP.new(rsakey) 
  plaintext = rsakey.decrypt(b64decode(ciphertext)) 
  return plaintext

# Calculate private exponent from n, e, p, q
def getPrivate(n, e, p, q):
  d = modInv(e, (p-1)*(q-1))
  return RSA.construct((n, e, d, p, q, ))

# Factors of n expressed as (2^2281 - 1)(2^2203 - 1)
p = (pow(2, 2281)-1)
q = (pow(2, 2203)-1)

    
# Get public key
def getpubkey():
    with open('./pub.pem','rb') as f:
        pub = f.read()
        public_key = RSA.importKey(pub)
        
        n = public_key.n  #140816102882370072753963128960517081965880280303822400235001309160195926187868730723645674960568062473761002103307583098926327676818048971808675637139699318767264291797993510624508457914745131902730458707154587694229291440822570657047495880598540768909211668263294445392516077874925310419418057302897080960859
        e = public_key.e  #65537
        """
        pubkey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIh16Sa3YCppifETNml6gKa/Cy\n56AT/hxNJMx6zQmQuYvjEIBAbB4EnW346ewy1yRRVDBKVYrJTHbmw2nIHbQGP5QU\n8GDbRogM05RCkorSZjB03L8Zhpp1u7hi8/dhPnKbQnrCHrI+S5EAu4OK3yw/nh76\nKlBOb/G1+py02ESHWwIDAQAB'
        keyDER = b64decode(pubkey)
        seq = asn1.DerSequence()
        seq.decode(keyDER)
        #seq[0] = b'0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00'
        #seq[1] = b'\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xc8\x87^\x92kv\x02\xa6\x98\x9f\x113f\x97\xa8\nk\xf0\xb2\xe7\xa0\x13\xfe\x1cM$\xccz\xcd\t\x90\xb9\x8b\xe3\x10\x80@l\x1e\x04\x9dm\xf8\xe9\xec2\xd7$QT0JU\x8a\xc9Lv\xe6\xc3i\xc8\x1d\xb4\x06?\x94\x14\xf0`\xdbF\x88\x0c\xd3\x94B\x92\x8a\xd2f0t\xdc\xbf\x19\x86\x9au\xbb\xb8b\xf3\xf7a>r\x9bBz\xc2\x1e\xb2>K\x91\x00\xbb\x83\x8a\xdf,?\x9e\x1e\xfa*PNo\xf1\xb5\xfa\x9c\xb4\xd8D\x87[\x02\x03\x01\x00\x01'
        #keyPub = RSA.construct( (seq[0], seq[1]) )
        #key = RSA.importKey(keyDER)
        """
        

    return public_key,n,e

# Check if u send me the flag !
def check(cipher_text,pubkey,n,e):
    with open('./flag.enc','rb') as f:
        flag = f.read().strip()
        #mPWM4kial8Cp1AuygSB8Cw/dUX7FEKGZi5JEzN/Gc8EVY5N5F6IXU1eW4HiT7rzpkl42lVKMfclMdEruWd1cACE3pSM5YyX/rW06GwlFXwCf59RnlUBPBngTfe3lv5bs0q6S0Sk7Sx81hyaPcSJqEP8xJuBYANEVYyx5eKk2RGs=

        # Use binascii.hexlify to transfer byte string into integer
        # then use RSA to encrypt it
        #flag_enc = pubkey.encrypt(int(binascii.hexlify(flag),16),'')[0]
        
        C = int(binascii.hexlify(flag),16)
        Y =C * (X**e) % n

        d = SHA256.new()
        dd = SHA256.new()

        # use binascii.unhexlify to transfer integer into byte string
        d.update(binascii.unhexlify(hex(C)[2:-1]))
        try :
            dd.update(base64.b64decode(cipher_text))
        except TypeError:
            print ('base64 decode error!')
            sys.exit()

        if d.hexdigest() == dd.hexdigest():
            return 0
        return 1

# decrypt the cipher_text you send
def decrypt(cipher_text):
    with open('./priv.pem','rb') as f:
        priv = f.read()
        key = RSA.importKey(priv)
        try :
            text = key.decrypt(base64.b64decode(cipher_text))
        except TypeError:
            print ('base64 decode error!')
            sys.exit()

        print ('Decrypted message in base64 encoding format: ')
        print (base64.b64encode(text))


if __name__ == '__main__' :
    #alarm(60)
    sys.stdout=os.fdopen(sys.stdin.fileno(),"wb",0)
    key,n,e = getpubkey()

    cipher_text = input('Give me your encrypted message in base64 encoding format : ').strip()

    if check(cipher_text,key,n,e) :
        decrypt(cipher_text)
    else :
        print ('You wish!')
