# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import http
import httpx
import logging
import ssl
import typing

from httpcore import (
    AsyncByteStream,
    AsyncHTTPTransport,
    ByteStream,
)

from httpcore._async.connection import (
    AsyncHTTPConnection,
)

from ._auth import (
    AuthHandler,
    NoAuth,
)

from ._backends import (
    AsyncioBackend,
)

from ._utils import (
    Headers,
    URL,
)

HAS_SOCKS = True
try:
    from python_socks.async_.asyncio import Proxy
except ImportError:
    HAS_SOCKS = False


logger = logging.getLogger(__name__)


async def _new_connection(
    url: URL,
    timeout: typing.Dict,
    ssl_context: typing.Optional[ssl.SSLContext],
    backend: AsyncioBackend,
) -> AsyncHTTPConnection:
    scheme, host, port = url[:3]
    ssl_context = None if scheme == b"http" else ssl_context

    sock = await backend.open_tcp_stream(
        hostname=host,
        port=port,
        ssl_context=ssl_context,
        timeout=timeout,
    )
    return AsyncHTTPConnection(
        (scheme, host, port),
        ssl_context=ssl_context,
        socket=sock,
        backend=backend,
    )


async def _new_socks_connection(
    proxy_url: httpx.URL,
    target_url: URL,
    timeout: int,
    ssl_context: typing.Optional[ssl.SSLContext],
    backend: AsyncioBackend,
) -> AsyncHTTPConnection:
    if not HAS_SOCKS:
        raise ImportError("Need pypsrp[socks] to be installed")

    # python-socks doesn't natively understand socks5h, we adjust the
    # prefix and set rdns based on whether socks5h is set or not.
    scheme = proxy_url.scheme
    proxy_url = str(proxy_url)
    rdns = False
    if scheme == "socks5h":
        rdns = True
        proxy_url = proxy_url.replace("socks5h://", "socks5://", 1)

    proxy = Proxy.from_url(proxy_url, rdns=rdns)
    sock = await proxy.connect(dest_host=target_url.host, dest_port=target_url.port, timeout=timeout)

    if target_url.scheme == b"https":
        server_hostname = target_url.host
    else:
        server_hostname = None
        ssl_context = None

    sock = await backend.open_tcp_stream(
        sock=sock,
        server_hostname=server_hostname,
        ssl_context=ssl_context,
    )
    return AsyncHTTPConnection(
        target_url[:3],
        ssl_context=ssl_context,
        socket=sock,
        backend=backend,
    )


class AsyncWSManTransport(AsyncHTTPTransport):
    def __init__(
        self,
        auth: typing.Optional[AuthHandler] = None,
        ssl_context: ssl.SSLContext = None,
        keepalive_expiry: float = 60.0,
        proxy_url: typing.Optional[str] = None,
        proxy_auth: typing.Optional[AuthHandler] = None,
    ):
        # Connection options
        self._backend = AsyncioBackend()
        self._connection = None
        self._socket = None
        self._auth = auth or NoAuth()
        self._ssl_context = ssl_context
        self._keepalive_expiry = keepalive_expiry

        # Proxy options
        self._proxy_url = httpx.URL(proxy_url) if proxy_url else None
        self._proxy_auth = proxy_auth or NoAuth()

    async def handle_async_request(
        self,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: AsyncByteStream,
        extensions: typing.Dict,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        connection = await self._get_connection()

        if not connection:
            self._auth.reset()
            self._connection = connection = await self._create_connection(url, self._proxy_url, extensions)

        return await self._auth.handle_async_request(connection, method, url, headers, stream, extensions)

    async def aclose(self) -> None:
        if self._connection:
            await self._connection.aclose()
            self._connection = None

        # if self._socket:
        #    await self._socket.aclose()
        #    self._socket = None

    async def _create_connection(
        self,
        url: URL,
        proxy_url: typing.Optional[httpx.URL],
        extensions: typing.Dict,
    ):
        timeout = extensions.get("timeout", {})

        if not proxy_url:
            return await _new_connection(url, timeout, self._ssl_context, self._backend)

        if proxy_url.scheme in ["socks5", "socks5h"]:
            return await _new_socks_connection(proxy_url, url, timeout, self._ssl_context, self._backend)

        proxy_url = proxy_url.raw
        connection = await self._create_connection(proxy_url, None, extensions)

        try:
            if url[0] == b"http":
                return AsyncProxyConnection(proxy_url, connection, auth=self._proxy_auth)

            # CONNECT
            target = b"%b:%d" % (url[1], url[2])
            connect_url = proxy_url[:3] + (target,)
            connect_headers = [(b"Host", target), (b"Accept", b"*/*")]

            proxy_status_code = (
                await self._proxy_auth.handle_async_request(
                    connection,
                    b"CONNECT",
                    connect_url,
                    connect_headers,
                    ByteStream(b""),
                    extensions,
                    auths_header="Proxy-Authenticate",
                    authz_header="Proxy-Authorization",
                )
            )[0]

            if proxy_status_code < 200 or proxy_status_code > 299:
                try:
                    reason = http.HTTPStatus(proxy_status_code).phrase
                except ValueError:
                    reason = ""
                raise Exception(f"Proxy failed {proxy_status_code} {reason}")

            # Do start_tls on the connection.
            tls_sock = await connection.socket.start_tls(url[1], self._ssl_context, timeout)
            connection = AsyncHTTPConnection(
                url[:3],
                ssl_context=self._ssl_context,
                socket=tls_sock,
                backend=self._backend,
            )

        except Exception:
            await connection.socket.aclose()
            raise

        return connection

    async def _get_connection(self):
        connection = self._connection

        if not connection:
            return

        must_close = False

        # if connection.state == ConnectionState.IDLE:
        #    now = _time()
        #    if connection.is_socket_readable():  # or now >= connection.expires_at:
        #        must_close = True
        # else:
        #    must_close = True

        if must_close:
            await connection.aclose()
            self._connection = None

            await self._socket.aclose()
            self._socket = None

        return self._connection


class AsyncProxyConnection(AsyncHTTPTransport):
    def __init__(
        self,
        proxy_url: URL,
        connection: AsyncHTTPConnection,
        auth: AuthHandler = None,
    ):
        self.proxy_url = proxy_url
        self._connection = connection
        self._auth = auth or NoAuth()

    async def handle_async_request(
        self,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: AsyncByteStream,
        extensions: typing.Dict,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        scheme, host, port, path = url
        if port is None:
            target = b"%s://%b%b" % (scheme, host, path)
        else:
            target = b"%b://%b:%d%b" % (scheme, host, port, path)

        url = self.proxy_url[:3] + (target,)
        return await self._auth.handle_async_request(
            self._connection,
            method,
            url,
            headers,
            stream,
            extensions,
            auths_header="Proxy-Authenticate",
            authz_header="Proxy-Authorization",
        )

    async def aclose(self) -> None:
        await self._connection.aclose()
