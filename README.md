required libraries:
    pycryptodome
    Cryptography
    datetime

all files with hashtags in their names are admin functions to speed up testing use they are 
not official files used in the program. i repeat they are there for your convenience and would
be removed if the program was not being tested.

within each certificate generation file execution there will be a prompt to see if you would like to add a 
new trusted user, the answer "no" or an immediate enter will generate certificates, the answer "yes" will 
let you add a user provided you know the password, any other answer will be discounted as invalid.

password for root CA: password1
password for intermediate CA: password2

in case of certificate failure:
 execute the CRL clearer
 execute the trusted list reset
 execute intermediate certificate authority with no input for the new trusted user addition check

for the serial count, if you execute person 2 multiple times the count will fail after the first.
if you wish to continuously use person 2 you will need to encrypt something with person 1 first.
