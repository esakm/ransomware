from abc import ABC
from itertools import cycle
from algo import Algo


class XORAlgo(Algo, ABC):

    def __init__(self, key=None):
        if not key:
            self.key = "supersecretkey"
        else:
            self.key = key[0]

    def encrypt(self, input_file):
        with open(input_file, 'rb') as f:
            file = f.read()

        with open(input_file, 'wb') as op:
            op.write(bytes(a ^ b for a, b in zip(file, cycle(bytes(self.key, encoding='utf8')))))

    def decrypt(self, input_file):
        return self.encrypt(input_file)

    def configure_algo(self, **kwargs):
        pass
