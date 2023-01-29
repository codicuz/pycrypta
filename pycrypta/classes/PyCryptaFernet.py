from cryptography.fernet import Fernet

class PyCryptaFernet():
    '''
        Учимся шифровать с Fernet
    '''
    def test_fernet():
        '''Шифруем строку и расшифровываем строку'''
        
        key = Fernet.generate_key()
        print(key)
        f = Fernet(key)

        token = f.encrypt(b'A relly secret message.')

        print(token)
        print(f.decrypt(token))