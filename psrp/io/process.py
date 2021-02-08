# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import subprocess
import threading
import typing


class Process:

    def __init__(
            self,
            executable: str,
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        self.executable = executable
        self.arguments = arguments or []
        self._process = None

        self._write_lock = threading.Lock()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait()

    def open(self):
        pipe = asyncio.subprocess.PIPE
        arguments = [self.executable]
        arguments.extend(self.arguments)

        self._process = subprocess.Popen(
            arguments, stdin=pipe, stdout=pipe, stderr=pipe
        )

    def read(self):
        stdout = self._process.stdout.readline()

        if not stdout:
            stdout, stderr = self._process.communicate()
            if stderr:
                raise Exception(stderr.decode())

            return

        print("Read\t" + stdout.decode().strip())
        return stdout

    def write(self, data):
        with self._write_lock:
            print("Write\t" + data.decode().strip())
            self._process.stdin.write(data)
            self._process.stdin.flush()


class AsyncProcess(Process):

    def __init__(
            self,
            executable: str,
            arguments: typing.Optional[typing.List[str]] = None,
    ):
        super().__init__(executable, arguments)
        self._write_lock = asyncio.Lock()

    async def __aenter__(self):
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._process:
            self._process.kill()
            await self._process.wait()
            self._process = None

    async def open(self):
        pipe = asyncio.subprocess.PIPE
        self._process = await asyncio.create_subprocess_exec(
            self.executable, *self.arguments, stdin=pipe, stdout=pipe, stderr=pipe
        )

    async def read(self) -> typing.Optional[bytes]:
        async def read_pipe(name):
            pipe = getattr(self._process, name)
            output = await pipe.readline()
            return name, output

        tasks = [read_pipe(n) for n in ['stdout', 'stderr']]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        output = None

        for coro in done:
            name, output = await coro

            if output:
                if name == 'stderr':
                    raise Exception(output.decode())

            else:
                return

        for coro in pending:
            coro.cancel()

        print("Read\t" + output.decode().strip())
        return output

    async def write(
            self,
            data: bytes,
    ):
        async with self._write_lock:
            print("Write\t" + data.decode().strip())
            self._process.stdin.write(data)
            await self._process.stdin.drain()
