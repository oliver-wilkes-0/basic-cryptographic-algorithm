# person 2
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128, SHA256
from Crypto.Protocol.DH import key_agreement
from main import load_cert
from datetime import datetime, timezone
from intermediate_certificate_authority import revoke_leaf_certificate
from Crypto.Signature import DSS

# marking current time for certificate checking
current_time = datetime.now(timezone.utc)

# diffie hellman key exchange

# key derivation function
def kdf(x):
    return SHAKE128.new(x).read(32)

with open("person2_dif_ECC_private.pem", "rt") as f:
    personal_secret =  ECC.import_key(f.read())

with open("person1_dif_ECC_public.pem", "rt") as f:
    other_person_public =  ECC.import_key(f.read())

shared_secret_key = key_agreement(static_priv=personal_secret, static_pub=other_person_public, kdf=kdf)

# certificate loading error handelling
try:
    # loading of certificates
    first_person_cert = load_cert("person1_certificate.pem")

    intermediate_auth_cert = load_cert("intermediate_certificate.pem")

    # saving of certificate signage public key
    certificate_public_key = intermediate_auth_cert.public_key()

    # certificate verification error handelling
    try:

        # basic signature verification
        certificate_public_key.verify(
        first_person_cert.signature,
        first_person_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256())
        )
        
        # certificate temporal validity checker
        if first_person_cert.not_valid_before_utc < current_time < first_person_cert.not_valid_after_utc:

            # loading of necessary data
            with open("ciphertext.txt", "rb") as f:
                ciphertext = f.read()

            with open("ciphertext_tag.txt", "rb") as f:
                person_mac_tag = f.read()

            with open("nonce.txt", "rb") as f:
                nonce = f.read()

            # decryption error handelling 
            try:

                # ciphertext decryption function
                decryption = ChaCha20_Poly1305.new(key=shared_secret_key, nonce=nonce)
                decrypted_plaintext = decryption.decrypt_and_verify(ciphertext, received_mac_tag=person_mac_tag)

                # splitting of plaintext to get the serial count used
                printable_plaintext = decrypted_plaintext.split('#/#'.encode())

                # loading of stored serial count
                with open("ciphertext_serial_count.pem", "r") as f:
                    serial_count = f.read()

                # serial count setting to integer
                serial_count = int(serial_count)

                # checking of serial count used against serial count stored
                if int(str(printable_plaintext[1])[2:-1]) == (serial_count - 1):
                    
                    # incrementing serial count stored
                    serial_count = int(serial_count) + 1

                    # storing serial count
                    with open("ciphertext_serial_count.pem", "w") as f:
                        f.write(str(serial_count))

                    # loading ciphertext signature 
                    with open("ciphertext_sig.pem", "rb") as f:
                        signature = f.read()

                    with open("digital_sig_public_key.pem", "r") as f:
                        signature_public_key = ECC.import_key(f.read())

                    # creating a hash of the plaintext to check against
                    hash = SHA256.new(decrypted_plaintext)

                    # signature verifier creation
                    verifier = DSS.new(signature_public_key, 'fips-186-3')

                    # signature verification error handelling
                    try:
                        # signature verification before decrypted data output
                        verifier.verify(hash, signature)
                        print("decrypted Text:", printable_plaintext[0])

                    # signature failure
                    except:
                        print("Error: this message is not authentic")

                # serial count failure
                else:
                    print("Error: serial count failure")

            # decryption failure
            except:
                print("Error: MAC check failed")
                revoke_leaf_certificate("person1_certificate.pem", "person1_certificate_private_key.pem", "person1", str(first_person_cert.serial_number))
        
        # certificate temporal validity failure
        else:
            print("Error: certificate authentication failure, date time invalid")
            revoke_leaf_certificate("person1_certificate.pem", "person1_certificate_private_key.pem" , "person1", str(first_person_cert.serial_number))
        
    # certificate verification failure
    except:
        print("Error: certificate authentication failure")
        revoke_leaf_certificate("person1_certificate.pem", "person1_certificate_private_key.pem", "person1", str(first_person_cert.serial_number))

# certificate loading failure
except:
    print("failed to load certificate")

# key zeroisation
shared_secret_key = b"\x00" * 32