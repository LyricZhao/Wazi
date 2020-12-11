import sys


class EmptyCipher:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return data

    @staticmethod
    def decode(data: bytes) -> bytes:
        return data


class RSACipher:
    def __init__(self, public_key_path, private_key_path):
        with open(public_key_path) as file:
            self.n = int(file.readline())
            self.e = int(file.readline())
        with open(private_key_path) as file:
            assert self.n == int(file.readline())
            self.d = int(file.readline())

    @staticmethod
    def fast_exp(a, b, n) -> int:
        """
        Return (a ^ b) % n
        """
        k = 1
        a = a % n
        while b > 0:
            if b & 1:
                k = (k * a) % n
            a = (a * a) % n
            b = b >> 1
        return k

    @staticmethod
    def coder(data: bytes, a, n) -> bytes:
        integer = int.from_bytes(data, sys.byteorder)
        coded = RSACipher.fast_exp(integer, a, n)
        bytes_length = coded.bit_length() // 8 if coded.bit_length() % 8 == 0 else coded.bit_length() // 8 + 1
        return coded.to_bytes(bytes_length, sys.byteorder)

    def encode(self, data: bytes) -> bytes:
        return self.coder(data, self.e, self.n)

    def decode(self, data: bytes) -> bytes:
        return self.coder(data, self.d, self.n)