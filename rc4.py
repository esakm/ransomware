from abc import ABC
from algo import Algo


class RC4Algo(Algo, ABC):

    def __init__(self, key=None):
        if not key:
            self.key = "supersecretkey"
        else:
            self.key = key[0]

    def ksa(self):
        s = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + s[i] + ord(self.key[i % len(self.key)])) % 256
            s[i], s[j] = s[j], s[i]
        return s

    def encrypt(self, input_file):
        s = self.ksa()
        with open(input_file, 'rb') as f:
            file = f.read()

        i = j = 0

        with open(input_file, 'wb') as op:
            for byte in file:
                i = (i + 1) % 256
                j = (j + s[i]) % 256
                s[i], s[j] = s[j], s[i]
                op.write((byte ^ s[(s[i] + s[j]) % 256]).to_bytes(1, 'big'))

    def configure_algo(self, **kwargs):
        pass

    def decrypt(self, input_file):
        self.encrypt(input_file)
