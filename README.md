Dev: Daniel Mendes
Date: 5/23/22
Assignment: TOTP (3)

This program works as outlined in the requirements.
To execute the program in qr generation mode, type: 'python3 ./totp.py --generate-qr'
    This mode will generate a random base32 'secret' and form URI
        The 'secret' will be placed in a text file called 'secret.txt'
    A QR code corresponding to the URI will be generated and stored in 'testqr.jpg'

    It's important to execute this mode first as the second mode requires 'secret.txt' to be present
    It's also important to remember that the 'secret' is different every time
        Every time QR generation mode is run, a new instance in the Google authenticator app is needed

To execute the program in OTP generation mode, type: 'python3 ./totp.py --get-otp'
    This mode will generate the TOTP corresponding to the secret in secret.txt
        The mode will also print the remaining time for which the TOTP is active
        Then, the program will sleep until it expires
    Once the initial TOTP expires, a the new TOTP will automatically be printed
        THIS IS AN INFINITE LOOP; There is no way to exit this unless the program is interrupted. 
    

IMPORTANT NOTE:
    I only tested this program on an IOS version of google authenticator. It works on IOS at least.