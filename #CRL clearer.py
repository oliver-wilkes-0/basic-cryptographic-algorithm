#CRL clearer

# quick reset of both CRLs
with open("intermediate_certificate_authority_CRL.pem","w") as f:
    f.write("")

with open("root_certificate_authority_CRL.pem", "w") as f:
    f.write("")
