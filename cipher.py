class EmptyCipher:
    @staticmethod
    async def encode(data: bytes) -> bytes:
        return data

    @staticmethod
    async def decode(data: bytes) -> bytes:
        return data
