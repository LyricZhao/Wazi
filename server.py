import argparse
import asyncio
import socket

from cipher import RSACipher, AESCipher, Hash


class Server:
    buffer_size = 1024

    def __init__(self, loop, addr, private_key_path, password_path):
        self.loop = loop
        self.addr = addr
        self.ip_aes_pool = {}

        with open(password_path, "r") as f:
            username, password = f.readlines()
            self.password = "".join([username.strip(), password.strip()]).encode()

        self.rsa = RSACipher(private_key_addr=private_key_path)
        self.hash = Hash()

    def run(self):
        self.loop.create_task(self.listen())
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print("Remote server shuts down")

    async def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as src_socket:
            src_socket.setblocking(False)
            src_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            src_socket.bind(self.addr)
            src_socket.listen(socket.SOMAXCONN)

            print("Listening at {}:{}".format(self.addr[0], self.addr[1]))
            while True:
                src_conn, src_addr = await self.loop.sock_accept(src_socket)
                self.loop.create_task(self.handle(src_conn, src_addr))

    async def handle(self, src_conn, src_addr):
        src_ip, _ = src_addr
        data = await self.loop.sock_recv(src_conn, self.buffer_size)

        # Handshake by hash
        hit = False
        if len(data) >= 4:
            h = data[0: 4]
            if h in self.hash.hash_tuple(self.password):
                # print(" > Detect hash hit")
                data = self.rsa.decode(data[4:])

                if len(data) < 16:
                    src_conn.close()
                    return

                password = data[16:]
                if password != self.password:
                    # print(" > Wrong password, close connection")
                    src_conn.close()
                    return
                
                print(" > Correct Password and exchange AES key with {}".format(src_ip))
                hit = True
                R = data[:16]
                self.ip_aes_pool[src_ip] = AESCipher(R)
                ok_data = b"OK"
                ok_data = self.ip_aes_pool[src_ip].encode(ok_data)
                await self.loop.sock_sendall(src_conn, ok_data)

        if hit:
            print(" > Authentication OK")
        else:
            if src_ip not in self.ip_aes_pool:
                src_conn.close()
                return
            else:

                # 1. Method negotiation
                # noinspection PyBroadException
                try:
                    aes = self.ip_aes_pool[src_ip]
                    data = self.unpack_decode(data, aes)
                    assert data and data[0] == 0x05
                except Exception:
                    src_conn.close()
                    return

                # 2. Send response, select a method. Choose 0x00 for no verification
                response_data = self.pack_encode(bytearray((0x05, 0x00)), aes)
                await self.loop.sock_sendall(src_conn, response_data)

                # 3. Request
                data = await self.loop.sock_recv(src_conn, self.buffer_size)
                data = self.unpack_decode(data, aes)

                if len(data) < 7:
                    src_conn.close()
                    return
    
                if data[1] != 0x01:
                    # Ensure connect
                    src_conn.close()
                    return

                dst_family = None
                dst_socket = None
                dst_addr = None
                dst_port = data[-2:]
                dst_port = int(dst_port.hex(), 16)
    
                if data[3] == 0x01:
                    # IPv4 address
                    dst_ip = socket.inet_ntop(socket.AF_INET, data[4:4 + 4])
                    dst_addr = (dst_ip, dst_port)
                    dst_family = socket.AF_INET
                elif data[3] == 0x03:
                    # URL
                    dst_ip = data[5:-2].decode()
                elif data[3] == 0x04:
                    # IPv6 address
                    dst_ip = socket.inet_ntop(socket.AF_INET6, data[4:4 + 16])
                    dst_addr = (dst_ip, dst_port, 0, 0)
                    dst_family = socket.AF_INET6
                else:
                    src_conn.close()
                    return

                if dst_family is not None:
                    # noinspection PyBroadException
                    try:
                        dst_socket = socket.socket(family=dst_family, type=socket.SOCK_STREAM)
                        dst_socket.setblocking(False)
                        await self.loop.sock_connect(dst_socket, dst_addr)
                    except Exception:
                        if dst_socket is not None:
                            dst_socket.close()
                            dst_socket = None
                else:
                    for info in await self.loop.getaddrinfo(dst_ip, dst_port):
                        dst_family, socket_type, proto, _, dst_addr = info
                        # noinspection PyBroadException
                        try:
                            dst_socket = socket.socket(family=dst_family, type=socket_type, proto=proto)
                            dst_socket.setblocking(False)
                            await self.loop.sock_connect(dst_socket, dst_addr)
                            break
                        except Exception:
                            if dst_socket is not None:
                                dst_socket.close()
                                dst_socket = None

                if dst_family is None:
                    return

                # 4. End negotiation
                end_data = self.pack_encode(
                    bytearray((0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)), aes)
                await self.loop.sock_sendall(src_conn, end_data)

                src_to_dst_task = self.loop.create_task(self.recv_and_send(src_conn, dst_socket,
                                                                           True, False, aes.decode))
                dst_to_src_task = self.loop.create_task(self.recv_and_send(dst_socket, src_conn,
                                                                           False, True, aes.encode))

                def clean_up(_):
                    dst_socket.close()
                    src_conn.close()
                asyncio.gather(src_to_dst_task, dst_to_src_task, loop=self.loop, return_exceptions=True).\
                    add_done_callback(clean_up)

    @staticmethod
    def unpack_decode(data, cipher):
        data = data[32:]
        return cipher.decode(data)

    @staticmethod
    def pack_encode(data, cipher):
        data = cipher.encode(data)
        return cipher.encode(int(len(data)).to_bytes(16, "little")) + data

    async def recv_and_send(self, src, dst, unpack_src_length, pack_dst_length, cipher_func):
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
                data = cipher_func(int(len(data)).to_bytes(16, "little")) + data
            await self.loop.sock_sendall(dst, data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazi Remote: A Light Proxy Remote Server")
    parser.add_argument("-p", help="Server port, default: 8388", metavar="SERVER_PORT", type=int, default=8388)
    parser.add_argument("-k", help="Private key path, default: private_key",
                        metavar="PRIVATE_KEY", type=str, default="private_key")
    parser.add_argument("-pw", help="Password path, default: password",
                        metavar="PASSWORD_PATH", type=str, default="password")
    args = parser.parse_args()

    print("Remote server starts running")
    server = Server(asyncio.get_event_loop(), ("0.0.0.0", args.p), args.k, args.pw)
    server.run()
