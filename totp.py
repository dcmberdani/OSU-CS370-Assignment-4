import argparse
from email.mime import base #arguments
import hashlib
from sys import byteorder
from tkinter.tix import Tree #arguments
import qrcode #qr codes

import struct # Another byteorder 

#Generating a random string in b32
import random 
import base64

#For time counter
import time

#For HOTP
from hashlib import sha1
import hmac

import pyotp # for testing

parser = argparse.ArgumentParser(description = "Just parses the arguments")
parser.add_argument("--generate-qr", help="Mode used in order to generate a key/QR pair and save them to here.", action='store_true')
parser.add_argument("--get-otp", help="Mode used to generate an OTP corresponding to the previously generated key.", action='store_true')
args = parser.parse_args()

def genb32str():
    randBytes = random.randbytes(10) # Enough bytes to generate a 16-len b32 str
    randb32bytes = base64.b32encode(randBytes)
    randstr =  randb32bytes.decode('utf-8') # Gets the string equivalent of a 32-bit nm 
    return randstr

def genqr():
    #Format for the thing we're storing in a qr code
    #   otpauth://TYPE/LABEL?PARAMETERS
    #   otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
    keyformat = 'otpauth://totp/'
    username = 'TestUser2'
    #secretcode = genb32str()  # random b32 value
    secretcode = 'ABCDEFGHIJKLMNOP' #non-random b32 value
    label = 'TestOrg:' + username 
    secret = 'secret=' + secretcode
    finalKey = keyformat + label + '?' + secret + '&issuer=Example&period=30'
    
    #Once the key is made, then make the qrcode; Save the qrcode/secretkey
    print(finalKey)
    
    with open('./secret.txt', 'w') as f:
        f.write(secretcode)
    
    img = qrcode.make(finalKey)
    img.save("testqr.jpg")

#Generates the counter aspect of the totp
def genctr():
    #https://datatracker.ietf.org/doc/html/rfc6238
    #First, grab current time and cast it from float to int
    currtime = int(time.time())
    #print("CURRTIME: " + str(currtime))
    
    #Then, set a time interval; This is 30 seconds
    timeintv = 30
    starttime = 0 #Start of an epoch; I think this is default 0
    
    #Now, calculate the counter value when all these are together;
    #   This number basically generates a new int every 30 seconds that is 1 greater than the last int
    ctr = (currtime - starttime) // timeintv
    
    print(ctr)
    
    return ctr
    
    
def genhotp(ctr):
    # MASSIVELY USEFUL SOURCE: https://datatracker.ietf.org/doc/html/rfc4226
    # First grab the key from the file
    with open("./secret.txt") as f:
       secretkey = f.read()

    # Get the key/ctr bytes to prepare for hashing
    keybytes = base64.b32decode(secretkey)
    # Source for packing integers as big-endian: https://docs.python.org/3/library/struct.html
    # Not sure why storing the counter as long-long bytes works but it does; Int does NOT work
    ctrbytes = struct.pack('>Q', ctr)  
    

    #Generate an HMAC with secret key as the key, and the counter as the message
    h = hmac.new(keybytes, msg=ctrbytes, digestmod=hashlib.sha1)
    #h = hmac.new(base64.b32decode(secretkey), struct.pack('>Q', ctr), hashlib.sha1)
    
    longhash = h.digest()

    #Now truncate the hash according to: https://datatracker.ietf.org/doc/html/rfc4226#section-5.3    
    #Both of these operations are taken almost directly from the above link
    # Grab the last nibble, use that as the offset to grab 4 bytes
    offset = longhash[len(longhash)-1] & 0xf 
    
    # Then, convert those last 4 bytes into an int; MSB is masked (set to 0) as per link requires
    longint = ((longhash[offset] & 0x7f) << 24) \
        |((longhash[offset + 1] & 0xff) << 16) \
        |((longhash[offset + 2] & 0xff) << 8) \
        |(longhash[offset + 3] & 0xff)
    
    # Finally, mod by 10^n in order to get a n-digit integer that is used as the code
    finalint = (longint % (1000000))
    print(finalint)
    
    #return finalint

#Combines the counter and hotp functions to generate the full totp
def gentotp():   
    ctr = genctr()
    totp = genhotp(ctr)
    
    print("NOW USING PYOTP")
    with open('./secret.txt', 'r') as f:
        secret = f.read()
    #hotp = pyotp.TOTP("ABCDEFGHIJKLMNOP")
    ptotp = pyotp.TOTP(secret)
    print(ptotp.now())


def main():
    if args.generate_qr:
        genqr()

        
    if args.get_otp:
        gentotp()    

main()