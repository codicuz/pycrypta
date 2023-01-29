from pycrypta.classes.PyCryptaWorker import PyCryptaWorker
from pycrypta.classes.PyCryptaX509SSCert import PyCryptaX509SSCert

class PyCryptaWorker(PyCryptaWorker): ...
class PyCryptaX509SSCert(PyCryptaX509SSCert): ...

def get_pycrypta_worker():
    return PyCryptaWorker()