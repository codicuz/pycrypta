import pycrypta

def main():
    print('Hello, pyCrypta!')

def test_fernet():
    f = pycrypta.get_pycrypta_worker()
    f.test_fernet()
    
def create_self_signet_cert():
    x509 = pycrypta.PyCryptaX509SSCert()
    ca_key = x509.create_private_key('ca.key.pem')
    x509.create_csr(ca_key)
    x509.create_self_signed_cert(ca_key)

def create_ca():
    x509 = pycrypta.PyCryptaX509SSCert()
    
    x509.create_private_key('ca')
    ca_key = x509.get_private_key_from_file('ca.key.pem')
    x509.create_ca('ca', ca_key)

def create_certificate():
    x509 = pycrypta.PyCryptaX509SSCert()
    
    ca_key = x509.get_private_key_from_file('ca.key.pem')
    
    x509.create_private_key('codicus.ru')
    certificate_key = x509.get_private_key_from_file('codicus.ru.key.pem')
    x509.create_csr('codicus.ru', certificate_key)

    csr = x509.get_csr_from_file('codicus.ru.csr.pem')
    ca_certififcate = x509.get_ca_certififcate('ca.crt.pem')
    x509.create_ceritificate(ca_certififcate, csr, 'codicus.ru', ca_key)


if __name__ == '__main__':
    main()
    # test_fernet()
    # create_self_signet_cert()
    create_ca()
    create_certificate()