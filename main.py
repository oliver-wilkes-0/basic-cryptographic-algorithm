# main
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes

# certificate creation function
def create_certificate(subject_name, list_of_approved_users, issuer, issuer_signage_key):

    # subject trusted check
    if subject_name not in list_of_approved_users:
        print("ERROR: user is not trusted")
        return None

    # certificate key generation
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    public_key = private_key.public_key()

    # subject and issuer assigning
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer),])

    # validity time frame setting
    current_time = datetime.now(timezone.utc) 
    expiration_time = current_time + timedelta(days=365)

    # serial number generation
    serial_number = x509.random_serial_number()
    
    # serial list and CRL list loading
    with open(str(issuer)[9:-2]+"_"+"serial_list.pem", "r") as f:
        serial_list = f.read()

    with open(str(issuer)[9:-2]+"_"+"CRL.pem", "r") as f:
        CRL_serial_list = f.read()

    # subject blacklisted check
    if subject_name in CRL_serial_list:
        return None

    # serial number already existing check
    while str(serial_number) in serial_list or str(serial_number) in CRL_serial_list:
        serial_number = x509.random_serial_number()

    # storage of new serial number in appropriate serial list
    with open(str(issuer)[9:-2]+"_"+"serial_list.pem", "a") as f:
        f.write("\n"+str(serial_number))

    # certificate creation
    certificate = x509.CertificateBuilder().subject_name(subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        serial_number
    ).not_valid_before(
        current_time
    ).not_valid_after(
        expiration_time
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(subject_name)]),
        critical=False
    ).sign(issuer_signage_key, hashes.SHA256(), default_backend)

    # return values
    return private_key, certificate

# certificate loading function
def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


