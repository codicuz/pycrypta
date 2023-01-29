from pycrypta.classes.PyCryptaFernet import PyCryptaFernet
from pycrypta.classes.PyCryptaX509SSCert import PyCryptaX509SSCert

class PyCryptaWorker(PyCryptaFernet, PyCryptaX509SSCert):
    '''Класс PyCryptaWorker'''
    @staticmethod
    def test_fernet():
        '''Функция для тестирования шифрования и расшифрования'''
        return PyCryptaFernet.test_fernet()