from algo import Algo
import random
from itertools import dropwhile
from abc import ABC


class ECCAlgo(Algo, ABC):

    def __init__(self, key=None):
        self.p = (2 ** 192) - (2 ** 64) - 1
        self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
        self.b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

        self.gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
        self.gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        self.h = 0x01
        self.x = 0x8DA78631011ED6B24CDD573F977FFFFFFFFFFFFFFFF21
        self.map_inverse = ECCAlgo._multiplicative_inverse(self.gx, self.n)
        self.public_key = (self.x * self.gx) % self.n

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
        with open(input_file, 'rb') as fd:
            data = fd.read()

        blocks = list(data[i:i + 16] for i in range(0, len(data), 16))
        ciphertext = []

        for block in blocks:
            num_of_zeros = self.count_zeros(block)
            block_as_int = int.from_bytes(block, 'big')
            mapped_block = (block_as_int * self.gx) % self.n
            k = random.randint(1, self.n - 1)
            c1 = (k * self.gx) % self.n
            c2 = (k * self.public_key) % self.n
            ciphertext.append((c1.to_bytes(24, 'big'), ((c2 + mapped_block) % self.n).to_bytes(24, 'big'), num_of_zeros))

        with open(input_file, "wb") as fd:
            for ciphertext_block in ciphertext:
                fd.write(ciphertext_block[0])
                fd.write(ciphertext_block[1])
                fd.write(ciphertext_block[2].to_bytes(1, 'big'))

    def decrypt(self, input_file):
        with open(input_file, "rb") as fd:
            data = fd.read()

        blocks = list(data[i:i + 49] for i in range(0, len(data), 49))
        plain_text = []
        for block in blocks:
            if block == b'':
                continue
            c = block[0:24]
            d = block[24:48]
            num_of_zeroes = block[-1]

            c2 = (self.x * int.from_bytes(c, 'big')) % self.n

            m = (int.from_bytes(d, 'big') - c2) % self.n
            orig_message = (m * self.map_inverse) % self.n
            orig_message = orig_message.to_bytes(orig_message.bit_length() // 8 + 1, 'big')
            zeroes_at_top = self.count_zeros(orig_message)
            if num_of_zeroes != zeroes_at_top:
                diff = num_of_zeroes - zeroes_at_top
                if diff < 0:
                    orig_message = orig_message[abs(diff):]
                elif diff > 0:
                    bytes_to_fill = bytearray(diff)
                    block_as_bytes = bytearray(orig_message)
                    bytes_to_fill.extend(block_as_bytes)
                    orig_message = bytes(bytes_to_fill)
            plain_text.append(orig_message)

        with open(input_file, "wb") as fd:
            for block in plain_text:
                fd.write(block)

    def configure_algo(self, **kwargs):
        pass
