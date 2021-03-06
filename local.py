import argparse
import asyncio
import socket

from cipher import AESCipher, RSACipher, Hash


class WaziLocal:
    buffer_size = 1024

    def __init__(self, loop: asyncio.AbstractEventLoop, key: str, public_key_addr: str,
                 remote_addr, listen_addr) -> None:
        self.loop = loop
        self.remote_addr = remote_addr
        self.listen_addr = listen_addr
        self.aes_key = AESCipher.generate_key()
        self.aes = AESCipher(self.aes_key)
        self.share_aes_key(key, public_key_addr)

    def share_aes_key(self, key: str, public_key_addr: str):
        # noinspection PyBroadException
        try:
            # Prepare authentication
            rsa = RSACipher(public_key_addr)
            key = key.encode()
            hash_value = Hash().hash_tuple(key)[1]
            assert len(hash_value) == 4

            # Connect to remote and share AES key
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(self.remote_addr)
            remote.send(hash_value + rsa.encode(self.aes_key + key))

            # Verify response
            response = self.aes.decode(remote.recv(self.buffer_size))
            if response == b"OK":
                print("Successful authentication")
            else:
                raise ConnectionError("Response not correct")
            remote.close()
        except Exception as exception:
            print("Failed to do authentication: {}".format(exception))
            exit(-1)

    def run(self) -> None:
        self.loop.create_task(self.listen())
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print("Local server shuts down")

    async def listen(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(self.listen_addr)
            listener.listen(socket.SOMAXCONN)
            listener.setblocking(False)

            print("Local server starts successfully")
            # print("Listening for new connections ...")
            while True:
                client, addr = await self.loop.sock_accept(listener)
                self.loop.create_task(self.handle(client))

    async def handle(self, client: socket.socket) -> None:
        remote = await self.new_remote()

        # Communicators
        client2remote = self.loop.create_task(self.communicator(client, remote, False, True, self.aes.encode))
        remote2client = self.loop.create_task(self.communicator(remote, client, True, False, self.aes.decode))

        # Clean up
        def clean_up(_) -> None:
            client.close()
            remote.close()
            # print(" > Connections close: {}".format(addr))
        asyncio.gather(client2remote, remote2client, loop=self.loop, return_exceptions=True).add_done_callback(clean_up)

    async def new_remote(self) -> socket.socket:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.setblocking(False)
        await self.loop.sock_connect(remote, self.remote_addr)
        return remote

    async def communicator(self, src: socket.socket, dst: socket.socket,
                           unpack_src_length: bool, pack_dst_length: bool, cipher_func) -> None:
        while True:
            data = b""
            if unpack_src_length:
                running = True
                while len(data) < 32 and running:
                    packet = await self.loop.sock_recv(src, 32 - len(data))
                    if not packet:
                        running = False
                        break
                    data = data + packet
                if not running:
                    break
                assert len(data) == 32
                length = int.from_bytes(cipher_func(data), "little")
                data = b""
                while len(data) < length and running:
                    packet = await self.loop.sock_recv(src, min(self.buffer_size, length - len(data)))
                    if not packet:
                        running = False
                        break
                    data = data + packet
                if not running:
                    break
            else:
                data = await self.loop.sock_recv(src, self.buffer_size)
            if not data:
                break
            data = cipher_func(data)
            if pack_dst_length:
                encoded_length = cipher_func(int(len(data)).to_bytes(16, "little"))
                # `cipher_func` must encode 16 bytes into 32 bytes
                assert len(encoded_length) == 32
                data = encoded_length + data
            await self.loop.sock_sendall(dst, data)


if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(description="Wazi Local: A Light Proxy Local Server")
    parser.add_argument("-sa", help="Server address", metavar="SERVER_ADDRESS", type=str, default="106.52.13.105")
    parser.add_argument("-sp", help="Server port", metavar="SERVER_PORT", type=int, default="8388")
    parser.add_argument("-la", help="Local address, default: localhost",
                        metavar="LOCAL_ADDRESS", type=str, default="localhost")
    parser.add_argument("-lp", help="Local port, default: 1080", metavar="LOCAL_PORT", type=int, default=1080)
    parser.add_argument("-u", help="Username, default: admin", metavar="USER", type=str, default="admin")
    parser.add_argument("-p", help="Password, default: admin", metavar="PASSWORD", type=str, default="admin")
    parser.add_argument("-k", help="Public key address (path or HTTPS address) for remote server, default: public_key",
                        metavar="PUBLIC_KEY_ADDRESS", type=str, default="public_key")
    options = parser.parse_args()
    print("Options: {}".format(options))

    # Run local server
    wazi_local = WaziLocal(asyncio.get_event_loop(), options.u + options.p, options.k,
                           (options.sa, options.sp), (options.la, options.lp))
    wazi_local.run()
