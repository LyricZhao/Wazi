import argparse
import socket
import asyncio

from cipher import RSACipher, EmptyCipher, AESCipher, Hash

BUFFER_SIZE = 1024


class Server():
    def __init__(self, loop, host, port, pub_key_path, pri_key_path, passwd_path):
        self.loop = loop
        self.host = host
        self.port = port

        self.ip_key_pool = {}

        with open(passwd_path, "r") as f:
            self.passwd = f.readlines()[0].strip().encode()
        
        self.rsa_cipher = RSACipher(pub_key_path, pri_key_path)

        self.hash = Hash()

    async def run_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as src_socket:
            src_socket.setblocking(False)
            src_socket.bind((self.host, self.port))
            src_socket.listen(5)

            print("Listening at {}:{}".format(self.host, self.port))
            while True:
                src_conn, src_addr = await self.loop.sock_accept(src_socket)
                print("Receive from {}".format(src_addr))
                self.loop.create_task(self.handle(src_conn, src_addr))

    async def handle(self, src_conn, src_addr):
        # 1. Method Negotiation
        src_ip, _ = src_addr

        data = await self.loop.sock_recv(src_conn, BUFFER_SIZE)
    
        hit = False

        if len(data) >= 4:
            h = data[:4]
            print("h", h)
            print("tuple", self.hash.hash_tuple(self.passwd))
            if h in self.hash.hash_tuple(self.passwd):
                print("h in")
                data = self.rsa_cipher.decode(data[4:])

                if len(data) < 16:
                    print(" data < 16")
                    src_conn.close()
                    return

                passwd = data[16:]
                print("passwd", passwd.decode())
                if passwd != self.passwd:
                    print(src_ip, "wrong passward, close connection")
                    src_conn.close()
                    return

                hit = True

                R = data[:16]
                print("R", R)
                # self.ip_key_pool[src_ip] = AESCipher(R)
                self.ip_key_pool[src_ip] = EmptyCipher()

                print("sent OK")
                ok_data = b"OK"
                ok_data = self.ip_key_pool[src_ip].encode(ok_data)
                await self.loop.sock_sendall(src_conn, ok_data)

        if hit:
            print("hit:", hit)
        else:
            if src_ip not in self.ip_key_pool:
                print("h not in")
                src_conn.close()
                return
            else:
                aes_cipher = self.ip_key_pool[src_ip] # NOTE get from pool
    
                data = aes_cipher.decode(data)
                print("Receive Negotiation:", data)
    
                if not data or data[0] != 0x05:
                    src_conn.close()
                    return
    
                # 2. Send Response, select a method. Choose 0x00 for no verification
                response_data = bytearray((0x05, 0x00))
                response_data = aes_cipher.encode(response_data)
                await self.loop.sock_sendall(src_conn, response_data)
    
                # 3. Request
                data = await self.loop.sock_recv(src_conn, BUFFER_SIZE)
                data = aes_cipher.decode(data)
                print("Receive Request:", data)
    
                if len(data) < 7:
                    src_conn.close()
                    return
    
                if data[1] != 0x01:
                    # ensure connect
                    src_conn.close()
                    return
    
                dst_family = None
                dst_ip = None
                dst_port = data[-2:]
                dst_port = int(dst_port.hex(), 16)
    
                if data[3] == 0x01:
                    # ipv4 address
                    dst_ip = socket.inet_ntop(socket.AF_INET, data[4:4 + 4])
                    dst_addr = (dst_ip, dst_port)
                    dst_family = socket.AF_INET
                elif data[3] == 0x03:
                    # url
                    dst_ip = data[5:-2].decode()
                elif data[3] == 0x04:
                    # ipv6 address
                    dst_ip = socket.inet_ntop(socket.AF_INET6, data[4:4 + 16])
                    dst_addr = (dst_ip, dst_port, 0, 0)
                    dstFamily = socket.AF_INET6
                else:
                    src_conn.close()
                    return
    
                print("dst_ip", dst_ip)
                print("dst_port", dst_port)
    
                if dst_family is not None:
                    try:
                        dst_socket = socket.socket(
                            family=dst_family, type=socket.SOCK_STREAM)
                        dst_socket.setblocking(False)
                        await self.loop.sock_connect(dst_socket, dst_addr)
                    except Exception as e:
                        print("Caught exception", e)
                        if dst_socket is not None:
                            dst_socket.close()
                            dstServer = None
                else:
                    for info in await self.loop.getaddrinfo(dst_ip, dst_port):
                        dst_family, socket_type, proto, canonname, dst_addr = info
                        try:
                            dst_socket = socket.socket(family=dst_family, type=socket_type, proto=proto)
                            dst_socket.setblocking(False)
                            await self.loop.sock_connect(dst_socket, dst_addr)
                            break
                        except Exception as e:
                            print("Caught exception", e)
                            if dst_socket is not None:
                                dst_socket.close()
                                dst_socket = None
    
                if dst_family is None:
                    return
    
                print("send end")
                # 4. End negotiation
                end_data = bytearray((0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
                end_data = aes_cipher.encode(end_data)
                await self.loop.sock_sendall(src_conn, end_data)
    
                src_to_dst_task = self.loop.create_task(self.recv_and_send("src2dst", self.loop, src_conn, dst_socket, cipher_func=aes_cipher.decode))
                dst_to_src_task = self.loop.create_task(self.recv_and_send("dst2src", self.loop, dst_socket, src_conn, cipher_func=aes_cipher.encode))
    
                task = asyncio.gather(src_to_dst_task, dst_to_src_task, loop=self.loop, return_exceptions=True)
    
                def clean_up(task):
                    print("clean up")
                    dst_socket.close()
                    src_conn.close()
    
                task.add_done_callback(clean_up)

    async def recv_and_send(self, mode, loop, conn_from, conn_to, cipher_func):
        while True:
            data = await loop.sock_recv(conn_from, BUFFER_SIZE)
            if not data:
                break
            print("before encode", mode, data)
            data = cipher_func(data)
            print("end encode", mode, data)
            await loop.sock_sendall(conn_to, data)

        print(mode, "close")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8388)
    parser.add_argument("--pub_key_path", type=str, default="./public_key")
    parser.add_argument("--pri_key_path", type=str, default="./private_key")
    parser.add_argument("--passwd_path", type=str, default="./passwd")

    args = parser.parse_args()

    host = "0.0.0.0"
    port = args.port

    print("Start running")

    loop = asyncio.get_event_loop()

    server = Server(loop, host, port, args.pub_key_path, args.pri_key_path, args.passwd_path)

    task = loop.create_task(server.run_server())

    loop.run_forever()

if __name__ == "__main__":
    main()
