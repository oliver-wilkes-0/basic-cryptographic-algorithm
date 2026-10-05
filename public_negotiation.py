# public negotiation
from Crypto.PublicKey import ECC

# person 1 ecc generation for diffie hellman
person1 = ECC.generate(curve = "p256")
person1_publickey = person1.public_key()

# person 1 key exportation
with open("person1_dif_ECC_private.pem", "wt") as f:
    f.write(person1.export_key(format='PEM'))

with open("person1_dif_ECC_public.pem", "wt") as f:
    f.write(person1_publickey.export_key(format="PEM"))

# person 2 ecc generation for Diffie Hellman
person2 = ECC.generate(curve = "p256")
person2_publickey = person2.public_key()

# person 2 key exportation
with open("person2_dif_ECC_private.pem", "wt") as f:
    f.write(person2.export_key(format="PEM"))

with open("person2_dif_ECC_public.pem", "wt") as f:
    f.write(person2_publickey.export_key(format="PEM"))


