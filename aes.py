import random
from itertools import chain


class AESAlgo:

    s_box = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    ]

    # round constants
    rc = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
          0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
          0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
          0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39]

    rounds = {16: 11, 24: 13, 32: 15}

    def __init__(self, key=None):
        if key is not None:
            self.key = bytes(key[0], 'utf-8')
            if len(self.key) not in AESAlgo.rounds:
                raise ValueError("Invalid key size")
        else:
            self.key = bytes("Thats my Kung Fu", 'ascii')

        self.num_rounds = AESAlgo.rounds[len(self.key)]
        self.expanded_key = []
        self.expand_key()

    @staticmethod
    def shift_rows(word, rotation):
        new_word = [0, 0, 0, 0]
        for i, c in enumerate(word):
            new_word[i - rotation] = c
        return new_word

    @staticmethod
    def sub_bytes(word):
        new_word = []
        for byte in word:
            new_word.append(AESAlgo.s_box[(byte & 0xf0) >> 4][byte & 0x0f])
        return new_word

    # https://github.com/boppreh/aes/blob/master/aes.py used as reference for xtime and mix_columns
    @staticmethod
    def xtime(x):
        return (((x << 1) ^ 0x1b) & 0xff) if (x & 0x80) else (x << 1)

    def mix_columns(self, state):
        for i in range(4):
            t = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]
            u = state[0][i]
            state[0][i] ^= t ^ AESAlgo.xtime(state[0][i] ^ state[1][i])
            state[1][i] ^= t ^ AESAlgo.xtime(state[1][i] ^ state[2][i])
            state[2][i] ^= t ^ AESAlgo.xtime(state[2][i] ^ state[3][i])
            state[3][i] ^= t ^ AESAlgo.xtime(state[3][i] ^ u)
        return state

    @staticmethod
    def matrix_to_bytes(matrix):
        result = []
        for i in range(4):
            for j in range(4):
                result.append(matrix[j][i])
        return bytes(result)


    @staticmethod
    def add_round_key(state, key):
        r = []
        for i in range(len(state)):
            r.append(state[i] ^ key[i])
        return bytearray(r)
        # return bytearray(a ^ b for a, b in zip(state, key))

    def expand_key(self):
        # word size in bytes
        # follows https://en.wikipedia.org/wiki/AES_key_schedule
        word_size = 4
        N = len(self.key) // 4
        key_words = list(self.key[i:i + word_size] for i in range(0, len(self.key), 4))
        key_schedule = []
        for i in range(4 * self.num_rounds):
            if i < N:
                key_schedule.append([x for x in bytearray(key_words[i])])

            elif i >= N and i % N == 0:
                rcon = [AESAlgo.rc[i // N - 1], 0, 0, 0]
                curr = self.add_round_key(key_schedule[i - N], self.sub_bytes(self.shift_rows(key_schedule[-1], 1)))
                key_schedule.append([x for x in self.add_round_key(rcon, curr)])

            elif i >= N > 6 and i % N == 4:
                key_schedule.append([x for x in
                                     self.add_round_key(key_schedule[i - N], self.sub_bytes(key_schedule[-1]))])
            else:
                key_schedule.append([x for x in
                                     self.add_round_key(key_schedule[i - N], key_schedule[-1])])

        self.expanded_key = list(key_schedule[i:i + 4] for i in range(0, len(key_schedule), 4))

        for i in range(len(self.expanded_key)):
            t = self.expanded_key[i]
            self.expanded_key[i] = list(chain(t[0], t[1], t[2], t[3]))

    def _encrypt_block(self, state):
        state = self.add_round_key(state, self.expanded_key[0])
        for j in range(1, self.num_rounds):
            round_key = self.expanded_key[j]
            state_words = list(state[j:len(state):4] for j in range(0, len(state), 1))
            state_words = state_words[0:4]
            state_words[0] = self.sub_bytes(state_words[0])
            state_words[1] = self.sub_bytes(state_words[1])
            state_words[2] = self.sub_bytes(state_words[2])
            state_words[3] = self.sub_bytes(state_words[3])
            state_words[1] = self.shift_rows(state_words[1], 1)
            state_words[2] = self.shift_rows(state_words[2], 2)
            state_words[3] = self.shift_rows(state_words[3], 3)
            if j != self.num_rounds - 1:
                state_words = self.mix_columns(state_words)
            state_in_bytes = self.matrix_to_bytes(state_words)
            state = self.add_round_key(state_in_bytes, round_key)
        return state

    def _encrypt(self, data, input_file):
        blocks = list(data[i:i + 16] for i in range(0, len(data), 16))
        iv = random.randint(2 ** (10 * 8), 2 ** (16 * 8) - 1).to_bytes(16, 'big')

        prev_block = iv
        if len(blocks) == 0 or len(blocks[-1]) == 16:
            blocks.append(0xc0000000000000000000000000000000.to_bytes(16, 'big'))
        else:
            block = blocks[-1]
            block = bytearray(block)
            block.extend(0xC0.to_bytes(1, 'big'))
            block.extend(bytes(16 - len(block)))
            blocks[-1] = block

        with open(input_file, "wb") as fd:
            fd.write(iv)
            for i, block in enumerate(blocks):
                state = prev_block
                block_cipher_text = self._encrypt_block(state)
                result = self.add_round_key(block_cipher_text, block)
                prev_block = result
                fd.write(result)

    def _decrypt(self, data, input_file):
        blocks = list(data[i:i + 16] for i in range(0, len(data), 16))
        iv = blocks[0]
        blocks = blocks[1:]
        prev_block = iv

        with open(input_file, "wb") as fd:
            for i, block in enumerate(blocks):
                state = prev_block
                block_cipher_text = self._encrypt_block(state)
                result = self.add_round_key(block_cipher_text, block)
                prev_block = block
                if i == len(blocks) - 1:
                    if result != 0xc0000000000000000000000000000000.to_bytes(16, 'big'):
                        index = 0
                        for i in range(16):
                            if result[16 - i - 1] == 0xc0:
                                index = 16 - i - 1
                                break
                        result = result[:index]
                    else:
                        continue
                fd.write(result)

    def encrypt(self, input_file):
        with open(input_file, "rb") as fd:
            data = fd.read()

        self._encrypt(data, input_file)

    def decrypt(self, input_file):
        with open(input_file, "rb") as fd:
            data = fd.read()

        self._decrypt(data, input_file)
