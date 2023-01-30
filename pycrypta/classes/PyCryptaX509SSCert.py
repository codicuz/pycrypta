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
    def create_private_key():
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
        
        # Запишем наш ключ на диск для безопасного хранения
        with open('mykey.pem', 'wb') as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            
            # Для генерации ключа с паролем
            encryption_algorithm=serialization.BestAvailableEncryption(b"pass"),
            
            # Для генерации ключа без пароля
            # encryption_algorithm=serialization.NoEncryption()
        ))

        return key

    @staticmethod
    def create_csr(key):
        '''
            Далее нам нужно сгенерировать запрос на подпись сертификата. Типичный CSR содержит несколько деталей:
                Информация о нашем открытом ключе (включая подпись всего тела).
                Информация о том, кто мы .
                Информация о том, для каких доменов предназначен этот сертификат.
            
            После генерации CSR, мы можем передать наш CSR центру сертификации, который взамен выдаст нам сертификат.
        '''

        from cryptography import x509
        from cryptography.x509.oid import NameOID
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
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Описываем, для каких сайтов мы хотим этот сертификат
                x509.DNSName(u'codicus.ru'),
                x509.DNSName(u'gitlab.codicus.ru'),
                x509.DNSName(u'nexus.codicus.ru')
            ]),critical=False
            # Подписываем CSR нашим приватным ключом
        ).sign(key, hashes.SHA256(), backend=default_backend())

        # Записываем запрос на сертификат (CSR) на диск
        with open('csr.pem', 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
    
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
            x509.NameAttribute(NameOID.COMMON_NAME, u'Coducus CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Codicus inc.'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Codicus CA OU')
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
            ).add_extension(PyCryptaX509SSCert.get_key_usage(True, True, True, True, True, True, True, True, True), critical=False
            ).sign(key, hashes.SHA256(), default_backend())

        print(x509.AuthorityKeyIdentifier.oid.dotted_string)
        with open('ca.key.pem', 'wb') as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pass")))

        with open('ca.crt.pem', 'wb') as f:
            f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))