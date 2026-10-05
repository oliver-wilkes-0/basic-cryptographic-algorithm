# person 1
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHAKE128, SHA256
from Crypto.Protocol.DH import key_agreement

# Diffie Hellman key exchange

# key derivation function
def kdf(x):
    return SHAKE128.new(x).read(32)

with open("person1_dif_ECC_private.pem", "rt") as f:
    personal_secret =  ECC.import_key(f.read())

with open("person2_dif_ECC_public.pem", "rt") as f:
    other_person_public =  ECC.import_key(f.read())

shared_secret_key = key_agreement(static_priv=personal_secret, static_pub=other_person_public, kdf=kdf)

# nonce generation
nonce = get_random_bytes(12)

# plaintext input generation
plaintext =  input("data to encrypt: ").encode()

# loading, adding and saving of the serial count
with open("ciphertext_serial_count.pem", "rb") as f:
    serial_number = int(f.read())

plaintext = plaintext + "#/#".encode() + str(serial_number).encode()

serial_number = serial_number + 1

with open("ciphertext_serial_count.pem", "w") as f:
    f.write(str(serial_number))

# signature and signature key pair generation
ecc_key = ECC.generate(curve='P-256')

with open("digital_sig_private_key.pem", "w") as f:
    f.write(ecc_key.export_key(format='PEM'))    

with open("digital_sig_public_key.pem", "w") as f:
    f.write(ecc_key.public_key().export_key(format='PEM'))

sha = SHA256.new(plaintext)

# plaintext signage 
signer = DSS.new(ecc_key, 'fips-186-3')
signature = signer.sign(sha)

# encryption error handelling
try:
    # encryption function
    cipher = ChaCha20_Poly1305.new(key=shared_secret_key, nonce=nonce)
    ciphertext = cipher.encrypt_and_digest(plaintext)

    # saving of information
    with open("ciphertext_sig.pem", "wb") as f:
        f.write(signature)

    with open("ciphertext.txt", "wb") as f:
        f.write(ciphertext[0])

    with open("ciphertext_tag.txt", "wb") as f:
        f.write(ciphertext[1])

    with open("nonce.txt", "wb") as f:
        f.write(nonce)

# encryption failure
except:
    print("Error: encryption failure")

#key zeroisation
shared_secret_key = b"\x00" * 32
