import argparse
import socket
import asyncio

BUFFER_SIZE = 1024

async def listen(loop, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as src_socket:
        src_socket.setblocking(False)
        src_socket.bind((host, port))
        src_socket.listen(5)

        print("Listening at {}:{}".format(host, port))
        while True:
            src_conn, src_addr = await loop.sock_accept(src_socket)
            print("Receive from {}".format(src_addr))
            
            # 1. Method Negotiation
            data = await loop.sock_recv(src_conn, BUFFER_SIZE)
            print("Negotiation:", data)

            if not data or data[0] != 0x05:
                src_conn.close()
                continue

            # 2. Send Response, select a method. Choose 0x00 for no verification
            await loop.sock_sendall(src_conn, bytearray((0x05, 0x00)))

            # 3. Request
            data = await loop.sock_recv(src_conn, BUFFER_SIZE)
            print("Request:", data)

            if len(data) < 7:
                src_conn.close()
                continue

            if data[1] != 0x01:
                src_conn.close()
                continue

            dst_family = None
            dst_ip = None
            dst_port = data[-2:]
            dst_port = int(dst_port.hex(), 16)

            if data[3] == 0x01:
                # ipv4 address
                dst_ip = socket.inet_ntop(socket.AF_INET, data[4:4 + 4])
                dst_family = socket.AF_INET

            elif data[3] == 0x03:
                # url
                dst_ip = data[5:-2].decode()

            print("dst_ip", dst_ip)
            print("dst_port", dst_port)

            if dst_family:
                try:
                    dst_socket = socket.socket(family=dst_family, type=socket.SOCK_STREAM)
                    dst_socket.setblocking(False)
                    await loop.sock_connect(dst_socket, (dst_ip, dst_port))
                except OSError:
                    if dst_socket is not None:
                        dst_socket.close()
                        dstServer = None

            else:
                for info in await loop.getaddrinfo(dst_ip, dst_port):
                    dst_family, socket_type, proto, canonname, dst_addr = info
                    try:
                        dst_socket = socket.socket(family=dst_family, type=socket_type, proto=proto)
                        dst_socket.setblocking(False)
                        await loop.sock_connect(dst_socket, dst_addr)
                        break
                    except OSError:
                        if dst_socket is not None:
                            dst_socket.close()
                            dst_socket = None

            if dst_family is None:
                continue

            # 4. End negotiation
            await loop.sock_sendall(src_conn, bytearray((0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)))

            src_to_dst_task = loop.create_task(recv_and_send("src2dst", loop, src_conn, dst_socket))
            dst_to_src_task = loop.create_task(recv_and_send("dst2src", loop, dst_socket, src_conn))

            task = asyncio.gather(src_to_dst_task, dst_to_src_task, loop=loop, return_exceptions=True)

            def clean_up(task):
                print("clean")
                dst_socket.close()
                src_conn.close()

            task.add_done_callback(clean_up)
                    

async def recv_and_send(mode, loop, conn_from, conn_to):
    while True:
        data = await loop.sock_recv(conn_from, BUFFER_SIZE)
        print(mode, "Receive and send real data: ", data)
        if not data:
            break
        await loop.sock_sendall(conn_to, data)
    
    print(mode, "done")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    host = "0.0.0.0"
    port = args.port

    print("Start running")

    loop = asyncio.get_event_loop()

    task = loop.create_task(listen(loop, host, port))

    loop.run_forever()

if __name__ == "__main__":
    main()
