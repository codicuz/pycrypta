import pycrypta

def main():
    print('Hello, pyCrypta!')

def test_fernet():
    f = pycrypta.get_pycrypta_worker()
    f.test_fernet()
    

def create_self_signet_cert():
    x509 = pycrypta.PyCryptaX509SSCert()
    key = x509.create_private_key()
    x509.create_csr(key)
    x509.create_self_signed_cert(key)

def create_ca():
    x509 = pycrypta.PyCryptaX509SSCert()
    key = x509.create_private_key()
    x509.create_ca(key)


if __name__ == '__main__':
    main()
    # test_fernet()
    # create_self_signet_cert()
    create_ca()