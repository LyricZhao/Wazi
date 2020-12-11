import cipher
import timeit


if __name__ == '__main__':
    rsa = cipher.RSACipher("public_key", "private_key")
    encoded = rsa.encode(b"test information 12345678 +-*/")
    decoded = rsa.decode(encoded)
    print(decoded)
    # print(timeit.timeit(lambda: rsa.decode(encoded), number=100))  # 0.04s per decode

    aes = cipher.AESCipher(cipher.AESCipher.generate_key())
    encoded = aes.encode(b"test information 12345678 +-*/")
    decoded = aes.decode(encoded)
    print(decoded)
    # print(timeit.timeit(lambda: aes.decode(encoded), number=100))  # 0.000003s per decoding

    hash_func = cipher.Hash()
    h1, h2 = hash_func.hash_tuple(b"test information 12345678 +-*/")
    assert len(h1) == 4
    assert len(h2) == 4
    print(h1, h2)
