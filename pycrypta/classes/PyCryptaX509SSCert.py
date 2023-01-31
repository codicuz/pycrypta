class PyCryptaX509SSCert:
    '''
        Создание запроса на подпись сертификата (CSR)

        При получении сертификата от центра сертификации (ЦС) обычный порядок действий таков:
            1. Вы создаете пару закрытый/открытый ключ.
            2. Вы создаете запрос на сертификат, который подписан вашим ключом (чтобы доказать, что вы владеете этим ключом).
            3. Вы передаете свой CSR в ЦС (но не закрытый ключ).
            4. Центр сертификации подтверждает, что вы являетесь владельцем ресурса (например, домена), для которого хотите получить сертификат.
            5. ЦС выдает вам подписанный ими сертификат, который идентифицирует ваш открытый ключ и ресурс, для которого вы аутентифицированы.
            6. Вы настраиваете свой сервер для использования этого сертификата в сочетании с вашим закрытым ключом для трафика сервера.
    '''
    @staticmethod
    def create_private_key(key_file_name: str, key_pass:str = None):
        '''
            Генерация закрытого ключа.

            Если вы хотите получить сертификат от типичного коммерческого центра сертификации, вот как это сделать. 
            Во-первых, вам нужно сгенерировать закрытый ключ, мы сгенерируем ключ RSA (в настоящее время это наиболее распространенные типы ключей в Интернете).

            Если вы уже сгенерировали ключ, вы можете загрузить его с помощью load_pem_private_key()
        '''
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # Генерируем наш ключ
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        
        if key_pass:
            # Для генерации ключа с паролем
            encription = serialization.BestAvailableEncryption(key_pass.encode())
        else:
            # Для генерации ключа без пароля
            encription=serialization.NoEncryption()

        # Запишем наш ключ на диск для безопасного хранения
        with open(key_file_name + '.key.pem', 'wb') as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encription,
        ))
    
    @staticmethod
    def get_private_key_from_file(key_file_name:str, key_pass: str = None):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        with open(key_file_name, 'rb') as f:
            if key_pass:
                key = serialization.load_pem_private_key(f.read(), key_pass.encode(), default_backend())
            else:
                key = serialization.load_pem_private_key(f.read(), key_pass, default_backend())
            f.close()
        
        return key

    @staticmethod
    def create_csr(csr_file_name: str, certificate_key):
        '''
            Далее нам нужно сгенерировать запрос на подпись сертификата. Типичный CSR содержит несколько деталей:
                Информация о нашем открытом ключе (включая подпись всего тела).
                Информация о том, кто мы .
                Информация о том, для каких доменов предназначен этот сертификат.
            
            После генерации CSR, мы можем передать наш CSR центру сертификации, который взамен выдаст нам сертификат.
        '''

        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Генерируем запрос на сертификат (CSR)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Предоставляем сведения о том, кто мы такие
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'RU'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'MOSCOW'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'MOSCOW'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'CODICUS'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'codicus.ru')
            ])
            ).add_extension(x509.SubjectKeyIdentifier.from_public_key(certificate_key.public_key()), critical=False
            
            ).add_extension(PyCryptaX509SSCert.get_key_usage(digital_signature=True, content_commitment=True, key_encipherment=True), critical=False
            ).add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"codicus.ru"),
                    x509.DNSName(u"gitlab.codicus.ru"),
                    x509.DNSName(u"nexus.codicus.ru")
                    ]),
                critical=False,
            # Подписываем CSR нашим приватным ключом
            ).sign(certificate_key, hashes.SHA256(), backend=default_backend())
        
        # Записываем запрос на сертификат (CSR) на диск
        with open(csr_file_name + '.csr.pem', 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
            f.close()
    
    @staticmethod
    def get_csr_from_file(csr_file_name:str):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        with open(csr_file_name, 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())
            f.close()
        
        return csr
    
    @staticmethod
    def create_self_signed_cert(key):
        '''
            Хотя в большинстве случаев вам нужен сертификат, подписанный кем-то другим (например, центром сертификации),
            чтобы установить доверие, иногда вам нужно создать самозаверяющий сертификат. Самоподписанные сертификаты 
            не выдаются центром сертификации, вместо этого они подписываются закрытым ключом, соответствующим открытому 
            ключу, который они внедряют.

            Это означает, что другие люди не доверяют этим сертификатам, но это также означает, что их можно очень легко 
            выдать. Как правило, единственным вариантом использования самозаверяющего сертификата является локальное тестирование,
            когда вам не нужно, чтобы кто-то еще доверял вашему сертификату.

            Как и при создании CSR, мы начинаем с создания нового закрытого ключа
        '''

        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MOSCOW"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"MOSCOW"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"codiucs"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"codicus.ru"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"codicus.ru"),
                x509.DNSName(u"gitlab.codicus.ru"),
                x509.DNSName(u"nexus.codicus.ru")
                ]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256(), backend=default_backend())
        # Write our certificate out to disk.
        with open("certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    @staticmethod
    def create_ceritificate(ca_certificate, csr, certificate_file_name: str, ca_key, cert_key_pass = None):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        subject = PyCryptaX509SSCert.get_csr_from_file('codicus.ru.csr.pem')
        # subject = csr.subject
        issuer = ca_certificate.issuer

        cert = x509.CertificateBuilder(
            ).subject_name(
                subject.subject
            ).issuer_name(
                issuer
            ).public_key(
                subject.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
            # Sign our certificate with our private key
            ).sign(ca_key, hashes.SHA256(), backend=default_backend())
        
        # Write our certificate out to disk.
        with open(certificate_file_name + '.pem', "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def get_key_usage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False):
        from cryptography import x509
        return x509.KeyUsage(digital_signature, content_commitment, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only, decipher_only)

    @staticmethod
    def create_ca(key):
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MOSCOW"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"MOSCOW"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Codiucs inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Codicus CA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Codicus Authority Center")
        ])

        certificate = x509.CertificateBuilder(
            ).subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            ).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
            ).add_extension(PyCryptaX509SSCert.get_key_usage(key_cert_sign=True, crl_sign=True), critical=False
            ).sign(key, hashes.SHA256(), default_backend())

        with open('ca.crt.pem', 'wb') as f:
            f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
        
    @staticmethod
    def get_ca_certififcate(ca_certificate_file_name: str):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        with open(ca_certificate_file_name, 'rb') as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
            f.close()
        
        return ca_certificate