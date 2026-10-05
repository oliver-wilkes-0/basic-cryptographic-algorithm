# intermediate_authority
from cryptography.hazmat.primitives import serialization
from main import create_certificate
import os

# certificate revokation function
def revoke_leaf_certificate(file, file2, user, serial_number):
        
        # removal of certificate and certificate private key files
        os.remove(file)
        os.remove(file2)

        # removal of user from trusted list
        with open("intermediate_trusted_list.pem", "r") as f:
            trusted_users = f.read().split(", ")
        
        trusted_users.remove(user)

        with open("intermediate_trusted_list.pem", "w") as f:
            f.write(str(trusted_users)[1:-1].replace("'", ""))

        # user and serial number added to intermediate CRL
        with open("intermediate_certificate_authority_CRL.pem", "a") as f:
            f.write("\n"+str(user) + " " + serial_number)
        return None

# accidental program execution prevention 
if __name__ == "__main__":

    # loading of intermediate trusted list
    with open("intermediate_trusted_list.pem", "r") as f:
        trusted_users = f.read().split(", ")

    # loading of intermediate signage key
    with open("intermediate_private_key.pem", "rb") as f:
        intermediate_signage_key = serialization.load_pem_private_key(f.read(), None)

    # user addition check input
    adding_user_check = input("would you like to add a user? ")

    # user addition check
    if adding_user_check == "" or adding_user_check.lower() == "no":

        # certificate creation error handelling
        try:

            # creation of person 1 certificate
            private_key, certificate = create_certificate(u"person1", trusted_users, u"intermediate_certificate_authority", intermediate_signage_key)

            # storage of person 1 certificate private key
            with open("person1_certificate_private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),  
                ))

            # storage of person 1 certificate
            with open("person1_certificate.pem", "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            #creation of person 2 certificate
            private_key, certificate = create_certificate(u"person2", trusted_users, u"intermediate_certificate_authority", intermediate_signage_key)

            # storage of person 2 certificate private key
            with open("person2_certificate_private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),  
                ))

            # storage of person 2 certificate
            with open("person2_certificate.pem", "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # certificate creation failure
        except:
            print("ERROR: certificate creation is invalid")

    # user addition check
    elif adding_user_check.lower() == "yes":

        # password check input
        password_input = input("what is the intermediate CA password? ")

        # loading of intermediate password
        with open("intermediate_authority_password.pem", "r") as f:
            password = f.read()

        # password check
        if password_input == password:

            # user to be trusted input
            user_input = input("what user would you like to be trusted? ")

            # loading of trusted list
            with open("intermediate_trusted_list.pem", "r") as f:
                trusted_list = f.read().split(", ")
            
            # user already trusted check
            if user_input not in trusted_list:

                # storage of newly trusted user
                with open("intermediate_trusted_list.pem", "a") as f:
                    f.write(", " + user_input)

            # user already trusted failure
            else:
                print("user is already trusted")

        # password failure
        else:
            print("incorrect password")

    # invalid input for user addition check
    else:
        print("input invalid")
    
