from algo import Algo
from itertools import dropwhile
from math import gcd
from abc import ABC


class RSAAlgo(Algo, ABC):
    default_p = 174122723649882188616813704347301796230439786058654801861672933041590339075938689332594706651717763459916738927766486930310880138276417350334711085661864647823420227213139784477636864122735555188522347843502788515195197129424419813650761041502681386186155648315736598314314059849521467737343782221757020965569
    default_q = 139554773457380155626335363645419563517604648029245042407177226064167983967510948062645279434112613368224409072750970403500597252410705172669696135136345242383770869166632681911547399454546422670004835119539529887427254097900090872592599462434869475396773835867094910209915551786502416525725788493894853175597

    def __init__(self, key=None):
        self.e = 65537
        if not key:
            self.prime_a = self.default_p
            self.prime_b = self.default_q
        else:
            self.prime_a = int(key[0])
            self.prime_b = int(key[1])

        self.n = self.prime_a * self.prime_b
        self.totient = abs((self.prime_b - 1) * (self.prime_a - 1)) // gcd(self.prime_a - 1, self.prime_b - 1)
        self.d = RSAAlgo._multiplicative_inverse(self.e, self.totient)

    @staticmethod
    def _multiplicative_inverse(a, b):
        b0 = b
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        if old_s < 0:
            return old_s + b0
        else:
            return old_s

    def count_zeros(self, bytes_to_count):
        zeros_removed = list(dropwhile(lambda x: x == 0, bytes_to_count))
        return len(bytes_to_count) - len(zeros_removed)

    def encrypt(self, input_file):
        with open(input_file, "rb") as fd:
            data = fd.read()

        block_size = (self.n.bit_length() // 8) - 42
        plaintext_blocks = list(data[i:i + block_size] for i in range(0, len(data), block_size))
        ciphertext_blocks = []

        for block in plaintext_blocks:
            num_of_zeros = self.count_zeros(block)
            block_as_int = int.from_bytes(block, 'big')
            block_as_int = pow(block_as_int, self.e, self.n)
            ciphertext_blocks.append((block_as_int.to_bytes(256, 'big'), num_of_zeros))

        with open(input_file, "wb") as fd:
            for block in ciphertext_blocks:
                fd.write(block[0])
                fd.write(block[1].to_bytes(1, 'big'))

    def decrypt(self, input_file):
        with open(input_file, "rb") as fd:
            data = fd.read()

        ciphertext_blocks = list(data[i:i + 257] for i in range(0, len(data), 257))
        plaintext_blocks = []

        for block in ciphertext_blocks:
            if block == b'':
                continue
            num_of_zeros = block[-1]
            block = block[:-1]
            block_as_int = int.from_bytes(block, 'big')
            block_as_int = pow(block_as_int, self.d, self.n)
            block_as_bytes = block_as_int.to_bytes(block_as_int.bit_length() // 8 + 1, 'big')
            zeros_at_top = self.count_zeros(block_as_bytes)
            if num_of_zeros != zeros_at_top:
                diff = num_of_zeros - zeros_at_top
                if diff < 0:
                    block_as_bytes = block_as_bytes[abs(diff):]
                elif diff > 0:
                    bytes_to_fill = bytearray(diff)
                    block_as_bytes = bytearray(block_as_bytes)
                    bytes_to_fill.extend(block_as_bytes)
                    block_as_bytes = bytes(bytes_to_fill)

            plaintext_blocks.append(block_as_bytes)

        with open(input_file, "wb") as fd:
            for block in plaintext_blocks:
                fd.write(block)

    def configure_algo(self, **kwargs):
        pass
