"""Small source-restricted TCP hop. SSO TLS stays encrypted end to end."""
import asyncio
import os

SOURCES = set(os.environ['SSO_BRIDGE_SOURCES'].split(','))
TARGET = os.environ['SSO_BRIDGE_TARGET']
PORT = int(os.environ.get('SSO_BRIDGE_PORT', '19443'))
active = 0


async def handle(reader, writer):
    global active
    peer = writer.get_extra_info('peername')[0]
    if peer not in SOURCES or active >= 16:
        writer.close()
        return
    active += 1
    remote = None
    tasks = []
    try:
        upstream, remote = await asyncio.wait_for(asyncio.open_connection(TARGET, 443), 5)

        async def pipe(source, dest):
            while True:
                chunk = await asyncio.wait_for(source.read(32768), 60)
                if not chunk:
                    return
                dest.write(chunk)
                await asyncio.wait_for(dest.drain(), 15)

        tasks = [asyncio.create_task(pipe(reader, remote)), asyncio.create_task(pipe(upstream, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (writer, remote):
            if stream:
                stream.close()
                try:
                    await stream.wait_closed()
                except OSError:
                    pass
        active -= 1


async def main():
    server = await asyncio.start_server(handle, '0.0.0.0', PORT, limit=65536)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
