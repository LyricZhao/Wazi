import argparse
import asyncio
import socket

from cipher import EmptyCipher


class WaziLocal:
    buffer_size = 1024

    def __init__(self, loop: asyncio.AbstractEventLoop, remote_addr, listen_addr) -> None:
        self.loop = loop
        self.remote_addr = remote_addr
        self.listen_addr = listen_addr

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
            print("Listening for new connections ...")
            while True:
                client, addr = await self.loop.sock_accept(listener)
                self.loop.create_task(self.handle(client, addr))

    async def handle(self, client: socket.socket, addr) -> None:
        print(" > Incoming connection: {}".format(addr))
        remote = await self.new_remote()

        # Communicators
        client2remote = self.loop.create_task(self.communicator(client, remote, EmptyCipher.encode))
        remote2client = self.loop.create_task(self.communicator(remote, client, EmptyCipher.decode))

        # Clean up
        def clean_up(_) -> None:
            client.close()
            remote.close()
            print(" > Connections close: {}".format(addr))
        asyncio.gather(client2remote, remote2client, loop=self.loop, return_exceptions=True).add_done_callback(clean_up)

    async def new_remote(self) -> socket.socket:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.setblocking(False)
        await self.loop.sock_connect(remote, self.remote_addr)
        return remote

    async def communicator(self, src: socket.socket, dst: socket.socket, cipher_func) -> None:
        while True:
            data = await self.loop.sock_recv(src, self.buffer_size)
            if data is None:
                break
            data = cipher_func(data)
            await self.loop.sock_sendall(dst, data)


if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(description="Wazi: A light proxy")
    parser.add_argument("-sa", help="Server address", metavar="SERVER_ADDRESS", default="106.52.13.105")
    parser.add_argument("-sp", help="Server port", metavar="SERVER_PORT", type=int, default="8388")
    parser.add_argument("-la", help="Local address, default: localhost", metavar="LOCAL_ADDRESS", default="localhost")
    parser.add_argument("-lp", help="Local port, default: 1080", metavar="LOCAL_PORT", type=int, default=1080)
    parser.add_argument("-u", help="Username, default: admin", metavar="USER", default="admin")
    parser.add_argument("-p", help="Password, default: admin", metavar="PASSWORD", default="admin")
    options = parser.parse_args()
    print("Options: {}".format(options))

    # Run local server
    wazi_local = WaziLocal(asyncio.get_event_loop(), (options.sa, options.sp), (options.la, options.lp))
    wazi_local.run()

