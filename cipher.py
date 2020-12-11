import abc
import random

from Crypto.Cipher import AES


class Cipher:
    @abc.abstractmethod
    def encode(self, data: bytes) -> bytes:
        raise NotImplemented

    @abc.abstractmethod
    def decode(self, data: bytes) -> bytes:
        raise NotImplemented


class EmptyCipher(Cipher):
    def encode(self, data: bytes) -> bytes:
        return data

    def decode(self, data: bytes) -> bytes:
        return data


class RSACipher(Cipher):
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
        integer = int.from_bytes(data, "little")
        coded = RSACipher.fast_exp(integer, a, n)
        bytes_length = coded.bit_length() // 8 if coded.bit_length() % 8 == 0 else coded.bit_length() // 8 + 1
        return coded.to_bytes(bytes_length, "little")

    def encode(self, data: bytes) -> bytes:
        assert data
        return self.coder(data, self.e, self.n)

    def decode(self, data: bytes) -> bytes:
        assert data
        return self.coder(data, self.d, self.n)


class AESCipher(Cipher):
    def __init__(self):
        self.key = random.randint(0, 65535).to_bytes(16, "little")
        self.aes = AES.new(self.key)

    @staticmethod
    def pack(data: bytes) -> bytes:
        length = len(data)
        padding = b'' if length % 16 == 0 else b'\0' * (16 - length % 16)
        data = length.to_bytes(16, "little") + data + padding
        return data

    @staticmethod
    def unpack(data: bytes) -> bytes:
        length = int.from_bytes(data[0: 16], "little")
        return data[16: 16 + length]

    def encode(self, data: bytes) -> bytes:
        data = AESCipher.pack(data)
        return self.aes.encrypt(data)

    def decode(self, data: bytes) -> bytes:
        data = self.aes.decrypt(data)
        return AESCipher.unpack(data)
