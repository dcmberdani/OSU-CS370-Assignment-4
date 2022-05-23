Dev: Daniel Mendes
Date: 5/23/22
Assignment: TOTP (3)

This program works as outlined in the requirements.
To execute the program in qr generation mode, type: 'python3 ./totp.py --generate-qr'
    This mode will generate a random base32 'secret' and full URI according to given documentation
        The 'secret' will be placed in a text file called 'secret.txt'
    A QR code corresponding to the URI will be generated and stored in 'testqr.jpg'

    It's important to execute this mode first as the second mode requires 'secret.txt' to be present
    It's also important to remember that the 'secret' is different every time
        Every time QR generation mode is run, a new instance in the Google authenticator app is needed


To execute the program in OTP generation mode, type: 'python3 ./totp.py --get-otp'
    This mode will generate the TOTP corresponding to the secret in secret.txt
        The mode will also print the remaining time for which the TOTP is active
        Then, the program will sleep until the TOTP expires

    Once the initial TOTP expires, a the new TOTP will automatically be printed
    THIS IS AN INFINITE LOOP; There is no way to exit this unless the program is interrupted. 


FOR PASSWORDS:
    To use a password protected secret, add the -p flag to the QR generation mode
        Visually: 'python3 ./totp.py --generate-qr -p'
        You will be asked to type in a password for the file. It needs to be under 16 chars long or it'll be cut. 
        The password is used to encrypt the secret, but it is not stored locally. You must remember it. 

    When calling the OTP generation mode, no flag needs to be specified.
        You will be asked to type in a password. 
        If the password is correct, the program behaves as expected. 
        If it's incorrect, then the program will exit. 

    My implementation of the password function was inspired by Nathan Lim's on the discord. Thanks.

IMPORTANT NOTE:
    I only tested this program on an IOS version of google authenticator. It works on IOS at least.