from rsa import RSAAlgo
from xor import XORAlgo
from rc4 import RC4Algo
from aes import AESAlgo
from ecc import ECCAlgo

funcs = {"rsa": RSAAlgo, "xor": XORAlgo, "rc4": RC4Algo, "aes": AESAlgo, "ecc": ECCAlgo}


class AlgoFactory:
    @staticmethod
    def get_algo(algo_type, key):
        if algo_type in funcs:
            return funcs[algo_type](key=key)
        else:
            raise ValueError("Not in the list of Algorithms")
