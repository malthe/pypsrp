# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
Contains hacks required to use WSMan specific features with the httpcore library. These should hopefully be
fixed/exposed as a public function in httpcore so we aren't relying on internal implementation details.
"""

import asyncio
import socket
import ssl
import typing

from httpcore import (
    ConnectError,
    ConnectTimeout,
)

from httpcore._backends.asyncio import (
    AsyncioBackend as _AsyncioBackend,
    SocketStream,
    map_exceptions,
)


# FUTURE: Look into an AnyioBackend


class AsyncioBackend(_AsyncioBackend):
    async def open_tcp_stream(
        self,
        hostname: bytes,
        port: int,
        ssl_context: typing.Optional[ssl.SSLContext],
        timeout: typing.Dict,
        *,
        local_address: typing.Optional[str] = None,
        sock: typing.Optional[socket.socket] = None,
        server_hostname: typing.Optional[str] = None,
    ) -> SocketStream:
        # httpcore AsyncioBackend does not offer the ability to open a connection on an existing socket or pass in a
        # custom hostname for TLS verification. Both of these are required for SOCKS proxies.
        host = hostname.decode("utf-8")
        connect_timeout = timeout.get("connect")
        local_addr = None if local_address is None else (local_address, 0)

        exc_map = {asyncio.TimeoutError: ConnectTimeout, OSError: ConnectError}
        with map_exceptions(exc_map):
            stream_reader, stream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=ssl_context,
                    sock=sock,
                    server_hostname=server_hostname,
                    local_addr=local_addr,
                ),
                connect_timeout,
            )

            # The asyncio start_tls method has a hardcoded check for this attribute failing with TypeError if this
            # attribute isn't True. The SSL transport used is compatible with Start TLS so setting this here bypasses
            # that problem. This is used when creating a TLS connection which proxies to a TLS endpoint.
            # https://github.com/python/cpython/blob/d9151cb45371836d39b6d53afb50c5bcd353c661/Lib/asyncio/base_events.py#L1210-L1212
            # https://github.com/encode/httpcore/issues/254
            if not hasattr(stream_writer.transport, "_start_tls_compatible"):
                setattr(stream_writer.transport, "_start_tls_compatible", True)

            return SocketStream(stream_reader=stream_reader, stream_writer=stream_writer)
