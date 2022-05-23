import argparse #For arguments/flags
import qrcode #For qr codes

#For generating a random string in b32
import random 
import base64

import time #For time counter

#For HOTP
import hashlib #SHA1 used for the MAC
import hmac
import struct

# For Passwords
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

parser = argparse.ArgumentParser(description = "Just parses the arguments")
parser.add_argument("--generate-qr", help="Mode used in order to generate a key/QR pair and save them to here.", action='store_true')
parser.add_argument("-p", help="Flag used to see if the user wants to store a password protected file or not.", action='store_true')
parser.add_argument("--get-otp", help="Mode used to generate an OTP corresponding to the previously generated key.", action='store_true')
args = parser.parse_args()

def genb32str():
    randBytes = random.randbytes(10) # Enough bytes to generate a 16-len b32 str
    randb32bytes = base64.b32encode(randBytes)
    randstr =  randb32bytes.decode('utf-8') # Gets the string equivalent of a 32-bit nm 
    return randstr

#Source for idea of how to do password stuff: Nathan Lim in the discord
def encryptsec(password, secret): 
    password = password[:16] #cut off long passwords
    paddedpass = password.ljust(16, 'A')
    cipher = Cipher(algorithms.AES(paddedpass.encode('utf-8')), modes.ECB())
    encryptor = cipher.encryptor() 
    toenc = "!NOW--DECRYPTED!" + secret  # Added additional part to allow for identification
    encpass = encryptor.update(toenc.encode('utf-8')) + encryptor.finalize()
    #Store the encrypted password in base64
    encstr = base64.b64encode(encpass).decode('utf-8')
        
    return encstr

def decryptsec(password, secret): 
    password = password[:16] #cut off long passwords
    paddedpass = password.ljust(16, 'A')
    cipher = Cipher(algorithms.AES(paddedpass.encode('utf-8')), modes.ECB())
    decryptor = cipher.decryptor() 
    # Get the ciphertext stored in base64, then reverse the encryption
    decpass = decryptor.update(base64.b64decode(secret)) + decryptor.finalize()
    
    #This can crash, meaning a bad decode; If this happens, then return error
    try:
        decstr = decpass.decode('utf-8')
    except:
        print("That is an incorrect password. Exiting.")
        exit()
    
    #Check the first 16 chars for the flag; If it's there, return the secret; If not, exit
    if (decstr[:16] == '!NOW--DECRYPTED!'):
        return decstr[16:]
    else: 
        print("That is an incorrect password. Exiting.")
        exit()
    

def getsecret(): 
    with open("./secret.txt") as f:
       secretkey = f.readline().strip()
       if (secretkey == "!ENCRYPTED!"):
           secretkey = f.readline().strip()
           password = input("Type in a password for the file is the password for the file: ")
           secretkey = decryptsec(password, secretkey)
    #Grab the key, works both with and without a password
    return secretkey

    
#Generates a QR line according to the 
def genqr():
    #Format for the thing we're storing in a qr code
    #   otpauth://TYPE/LABEL?PARAMETERS
    #   otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
    secretcode = genb32str()  # random b32 value
    finalURL = 'otpauth://totp/CS370:Beaver?secret=' + secretcode + '&issuer=OSU&period=30'
    
    #Once the key is made, then make the qrcode; Save the qrcode/secretkey
    print("URL for QR: " + finalURL)
    
    if args.p:
        password = input("Type in a password UNDER 16 CHARS for 'secret.txt': ")
        encsecret = encryptsec(password, secretcode)
        with open('./secret.txt', 'w') as f:
            f.write("!ENCRYPTED!\n")
            f.write(encsecret)
    else:
        with open('./secret.txt', 'w') as f:
            f.write(secretcode)
    
    img = qrcode.make(finalURL)
    img.save("qrcode.jpg")

#Generates the counter aspect of the totp
def genctr():
    #https://datatracker.ietf.org/doc/html/rfc6238
    #First, grab current time and cast it from float to int
    currtime = int(time.time())
    
    #Then, set a time interval; This is 30 seconds
    timeintv = 30
    starttime = 0 #Start of an epoch; I think this is default 0
    
    #Now, calculate the counter value when all these are together;
    #   This number basically generates a new int every 30 seconds that is 1 greater than the last int
    #Also, calculate the remaining amount of time the code is valid for and print it
    #   This is timeint - (elapsed time); Elapsed time is simply the mod (not divide) of the ctr operation
    ctr = (currtime - starttime) // timeintv
    remtime = timeintv - ( (currtime - starttime) % timeintv )
    
    print("TOTP is valid for " + str(remtime) + " seconds.")
    
    return (ctr, remtime)
    
    
def genhotp(ctr, secretkey):
    # MASSIVELY USEFUL SOURCE: https://datatracker.ietf.org/doc/html/rfc4226

    # Get the key/ctr bytes to prepare for hashing
    keybytes = base64.b32decode(secretkey)
    # Source for packing integers as big-endian: https://docs.python.org/3/library/struct.html
    # Not sure why storing the counter as long-long bytes works but it does; Int does NOT work
    ctrbytes = struct.pack('>Q', ctr)  
    

    #Generate an HMAC with secret key as the key, and the counter as the message
    h = hmac.new(keybytes, msg=ctrbytes, digestmod=hashlib.sha1)
    longhash = h.digest()

    #Now truncate the hash according to: https://datatracker.ietf.org/doc/html/rfc4226#section-5.3    
    #Both of these operations are taken almost directly from the above link
    # Grab the last nibble, use that as the offset to grab 4 bytes
    offset = longhash[len(longhash) - 1] & 0xf 
    
    # Then, convert those last 4 bytes into an int; MSB is masked (set to 0) as per link requires
    longint = ((longhash[offset] & 0x7f) << 24) \
        |((longhash[offset + 1] & 0xff) << 16) \
        |((longhash[offset + 2] & 0xff) << 8) \
        |(longhash[offset + 3] & 0xff)
    
    # Finally, mod by 10^n in order to get a n-digit integer that is used as the code
    finalint = (longint % (1000000))
        
    return finalint

#Combines the counter and hotp functions to generate the full totp
def gentotp():
    #Get secret before loop since it's a one-time thing;
    secret = getsecret()   
    while (1):
        timetuple = genctr()
        totp = genhotp(timetuple[0], secret)
        print("TOTP: " + f"{totp:06d}" + '\n') # Print leading 0s: https://stackoverflow.com/questions/134934/display-number-with-leading-zeros
        #After printing out the code, wait until it expires then repeat.
        time.sleep(timetuple[1]) 

def main():
    if args.generate_qr:
        genqr()

        
    if args.get_otp:
        gentotp()    

main()