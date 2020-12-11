import abc
import random
import requests
import time

from Crypto.Cipher import AES


class Cipher:
    @abc.abstractmethod
    def encode(self, data: bytes) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def decode(self, data: bytes) -> bytes:
        raise NotImplementedError


class EmptyCipher(Cipher):
    def encode(self, data: bytes) -> bytes:
        return data

    def decode(self, data: bytes) -> bytes:
        return data


class RSACipher(Cipher):
    def __init__(self, public_key_addr="", private_key_addr=""):
        self.n = None
        self.e = None
        self.d = None

        if public_key_addr:
            if public_key_addr.startswith("https"):
                text = requests.get(public_key_addr).text
                self.n, self.e = text.split()
                self.n, self.e = int(self.n), int(self.e)
            else:
                with open(public_key_addr) as file:
                    self.n = int(file.readline())
                    self.e = int(file.readline())
        if private_key_addr:
            assert not private_key_addr.startswith("http")
            with open(private_key_addr) as file:
                self.n = int(file.readline())
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
        assert data and self.e and self.n
        return self.coder(data, self.e, self.n)

    def decode(self, data: bytes) -> bytes:
        assert data and self.e and self.n
        return self.coder(data, self.d, self.n)


class AESCipher(Cipher):
    def __init__(self, key):
        self.aes = AES.new(key)

    @staticmethod
    def generate_key():
        return random.randint(0, 2 ** 128).to_bytes(16, "little")

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


class Hash:
    def __init__(self):
        self.last_query = ""
        self.last_time = 0
        self.last_result = (b"", b"")

    @staticmethod
    def hash(query: bytes, seed: int) -> bytes:
        value = 0
        mod = 2 ** 32
        for byte in query:
            value = ((value ^ seed) * 131 + int(byte)) % mod
        return value.to_bytes(4, "little")

    def hash_tuple(self, query: bytes):
        current_time = int(time.time()) // 20
        if query == self.last_query and current_time == self.last_time:
            return self.last_result
        self.last_query = query
        self.last_time = current_time
        self.last_result = (Hash.hash(query, current_time - 1), Hash.hash(query, current_time))
        return self.last_result
