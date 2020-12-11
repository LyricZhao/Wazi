import cipher
import timeit


if __name__ == '__main__':
    rsa = cipher.RSACipher("public_key", "private_key")
    encoded = rsa.encode(b"test information 12345678 +-*/")
    decoded = rsa.decode(encoded)
    print(decoded)
    print(timeit.timeit(lambda: rsa.decode(encoded), number=100))  # 0.03s per decoding
