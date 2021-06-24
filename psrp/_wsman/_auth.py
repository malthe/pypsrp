# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import base64
import functools
import httpx
import logging
import re
import spnego
import spnego.channel_bindings
import typing

from httpcore import (
    AsyncByteStream,
    AsyncHTTPTransport,
    SyncByteStream,
    SyncHTTPTransport,
)

from ._bytestreams import (
    PlainByteStream,
)

from ._encryption import (
    decrypt_wsman,
    encrypt_wsman,
)

from ._utils import (
    get_tls_server_end_point_hash,
    Headers,
    URL,
)

logger = logging.getLogger(__name__)


WWW_AUTH_PATTERN = re.compile(r"(CredSSP|Kerberos|Negotiate|NTLM)\s*([^,]*),?", re.I)
WWW_AUTHS = "WWW-Authenticate"
WWW_AUTHZ = "Authorization"


def _async_wrap(func, *args, **kwargs):
    """Runs a sync function in the background."""
    loop = asyncio.get_running_loop()
    task = loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

    return task


class AsyncAuth:

    SUPPORTS_ENCRYPTION = False

    async def arequest(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        return await connection.arequest(method, url, headers=headers, stream=stream, ext=ext)

    def reset(self):
        pass


class SyncAuth:

    SUPPORTS_ENCRYPTION = False

    def request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: SyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        return connection.request(method, url, headers=headers, stream=stream, ext=ext)

    def reset(self):
        pass


class AsyncNoAuth(AsyncAuth):
    pass


class SyncNoAuth(SyncAuth):
    pass


class _NegotiateAuthBase:
    def __init__(
        self,
        credential: typing.Any = None,
        protocol: str = "negotiate",
        encrypt: bool = True,
        service: str = "HTTP",
        hostname_override: typing.Optional[str] = None,
        disable_cbt: bool = False,
        delegate: bool = False,
        credssp_allow_tlsv1: bool = False,
        credssp_require_kerberos: bool = False,
    ):
        super().__init__(self)
        valid_protocols = ["kerberos", "negotiate", "ntlm", "credssp"]
        if protocol not in valid_protocols:
            raise ValueError(f"{type(self).__name__} protocol only supports {', '.join(valid_protocols)}")

        self.protocol = protocol.lower()

        self._context = None
        self.__complete = False
        self._credential = credential
        self._encrypt = encrypt
        self._service = service
        self._hostname_override = hostname_override
        self._disable_cbt = disable_cbt
        self._delegate = delegate
        self._credssp_allow_tlsv1 = credssp_allow_tlsv1
        self._credssp_require_kerberos = credssp_require_kerberos

    @property
    def _complete(self) -> bool:
        return self.__complete or (self._context and self._context.complete)

    @property
    def _auth_header(self) -> str:
        return {
            "negotiate": "Negotiate",
            "ntlm": "Negotiate",
            "kerberos": "Kerberos",
            "credssp": "CredSSP",
        }[self.protocol]

    def reset(self):
        self._context = None
        self.__complete = False

    def _build_context(
        self,
        connection: typing.Union[AsyncHTTPTransport, SyncHTTPTransport],
        hostname: bytes,
    ):
        cbt = None
        ssl_object = None
        if hasattr(connection, "socket"):
            ssl_object = connection.socket.stream_writer.get_extra_info("ssl_object")

        if ssl_object and not self._disable_cbt and self.protocol != "credssp":
            cert = ssl_object.getpeercert(True)
            cert_hash = get_tls_server_end_point_hash(cert)
            cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-server-end-point:" + cert_hash)

        context_req = spnego.ContextReq.default
        spnego_options = spnego.NegotiateOptions.none

        if self._encrypt:
            spnego_options |= spnego.NegotiateOptions.wrapping_winrm

        if self.protocol == "credssp":
            if self._credssp_allow_tlsv1:
                spnego_options |= spnego.NegotiateOptions.credssp_allow_tlsv1

            if self._credssp_require_kerberos:
                spnego_options |= spnego.NegotiateOptions.negotiate_kerberos

        elif self._delegate:
            context_req |= spnego.ContextReq.delegate

        username, password = self._credential
        auth_hostname = self._hostname_override or hostname.decode("utf-8")
        return spnego.client(
            username,
            password,
            hostname=auth_hostname,
            service=self._service,
            channel_bindings=cbt,
            context_req=context_req,
            protocol=self.protocol,
            options=spnego_options,
        )

    def _add_header(self, headers: httpx.Headers, token: bytes, authz_header: str):
        headers[authz_header] = f"{self._auth_header} {base64.b64encode(token).decode()}"

    def _get_header_token(
        self,
        headers: httpx.Headers,
        auths_header: str,
    ) -> typing.Optional[bytes]:
        auths = headers.get(auths_header, "")
        in_token = WWW_AUTH_PATTERN.search(auths)
        if in_token:
            in_token = base64.b64decode(in_token.group(2))

        if not in_token:
            # Some proxies don't seem to return the mutual auth token which
            # break the _context.complete checker later on. Because mutual
            # auth doesn't matter for proxies we just override that check.
            self.__complete = True
            in_token = None

        return in_token

    def _wrap(
        self,
        headers: Headers,
        data: typing.Optional[bytearray] = None,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        temp_headers = httpx.Headers(headers)

        if self._encrypt and data:
            protocol = {
                "kerberos": "Kerberos",
                "credssp": "CredSSP",
            }.get(self.protocol, "SPNEGO")

            enc_data, content_type = encrypt_wsman(
                data, temp_headers["Content-Type"], f"application/HTTP-{protocol}-session-encrypted", self._context
            )
            temp_headers["Content-Type"] = content_type
            temp_headers["Content-Length"] = str(len(enc_data))

            stream = PlainByteStream(enc_data)

        elif not data:
            temp_headers["Content-Length"] = "0"

        return temp_headers, stream

    def _unwrap(
        self,
        headers: Headers,
        data: bytearray,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        temp_headers = httpx.Headers(headers)

        content_type = temp_headers.get("Content-Type", "")

        # A proxy will have these content types but cannot do the encryption so
        # we must also check for self._encrypt.
        if self._encrypt and (
            content_type.startswith("multipart/encrypted;") or content_type.startswith("multipart/x-multi-encrypted;")
        ):
            data, content_type = decrypt_wsman(data, content_type, self._context)
            temp_headers["Content-Length"] = str(len(data))
            temp_headers["Content-Type"] = content_type

        return temp_headers, PlainByteStream(bytes(data))


class AsyncNegotiateAuth(_NegotiateAuthBase, AsyncAuth):

    SUPPORTS_ENCRYPTION = True

    async def arequest(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        if not self._complete:
            self._context = await _async_wrap(self._build_context, connection, url[1])

            status_code = 500
            resp_headers = httpx.Headers()
            resp_stream = PlainByteStream(b"")

            send_headers, send_stream = await self._wrap_stream(headers, stream)
            in_token = None

            while not self._context.complete:
                out_token = await _async_wrap(self._context.step, in_token)
                if not out_token:
                    break

                self._add_header(send_headers, out_token, authz_header)
                status_code, resp_headers, resp_stream, ext = await connection.arequest(
                    method, url, headers=send_headers.raw, stream=send_stream, ext=ext
                )
                resp_headers, resp_stream = await self._unwrap_stream(resp_headers, resp_stream)

                in_token = self._get_header_token(resp_headers, auths_header)
                if not in_token:
                    break

            # If we didn't encrypt then the response from the auth phase
            # contains our actual response. Also pass along any errors back.
            if not self._encrypt or status_code != 200:
                return status_code, resp_headers.raw, resp_stream, ext

        headers, stream = await self._wrap_stream(headers, stream)
        status_code, headers, stream, ext = await connection.arequest(
            method, url, headers=headers.raw, stream=stream, ext=ext
        )
        headers, stream = await self._unwrap_stream(headers, stream)

        return status_code, headers.raw, stream, ext

    async def _wrap_stream(
        self,
        headers: Headers,
        stream: typing.Optional[AsyncByteStream] = None,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        data = bytearray()
        if self._encrypt and stream:
            async for b in stream:
                data += b

        return self._wrap(headers, data)

    async def _unwrap_stream(
        self,
        headers: Headers,
        stream: AsyncByteStream,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        data = bytearray()
        async for chunk in stream:
            data += chunk
        await stream.aclose()
        # self._connection.expires_at = _time() + self._keepalive_expiry

        return self._unwrap(headers, data)


class SyncNegotiateAuth(_NegotiateAuthBase, SyncAuth):

    SUPPORTS_ENCRYPTION = True

    def request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: SyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        if not self._complete:
            self._context = self._build_context(connection, url[1])

            status_code = 500
            resp_headers = httpx.Headers()
            resp_stream = PlainByteStream(b"")

            send_headers, send_stream = self._wrap_stream(headers, stream)
            in_token = None

            while not self._context.complete:
                out_token = self._context.step(in_token)
                if not out_token:
                    break

                self._add_header(send_headers, out_token, authz_header)
                status_code, resp_headers, resp_stream, ext = connection.request(
                    method, url, headers=send_headers.raw, stream=send_stream, ext=ext
                )
                headers, resp_stream = self._unwrap_stream(resp_headers, resp_stream)

                # If we didn't encrypt then the response from the auth phase
                # contains our actual response. Also pass along any errors back.
                in_token = self._get_header_token(resp_headers, auths_header)
                if not in_token:
                    break

            if not self._encrypt or status_code != 200:
                return status_code, resp_headers.raw, resp_stream, ext

        headers, stream = self._wrap_stream(headers, stream)
        status_code, headers, stream, ext = connection.request(method, url, headers=headers.raw, stream=stream, ext=ext)
        headers, stream = self._unwrap_stream(headers, stream)

        return status_code, headers.raw, stream, ext

    def _wrap_stream(
        self,
        headers: Headers,
        stream: typing.Optional[SyncByteStream] = None,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        data = bytearray()
        if self._encrypt and stream:
            for b in stream:
                data += b

        return self._wrap(headers, data)

    def _unwrap_stream(
        self,
        headers: Headers,
        stream: SyncByteStream,
    ) -> typing.Tuple[httpx.Headers, PlainByteStream]:
        data = bytearray()
        for chunk in stream:
            data += chunk
        stream.close()
        # self._connection.expires_at = _time() + self._keepalive_expiry

        return self._unwrap(headers, data)


class _BasicAuthBase:
    def __init__(
        self,
        username: str,
        password: str,
    ):
        super().__init__(self)
        credential = f'{username or ""}:{password or ""}'.encode("utf-8")
        self._token = f"Basic {base64.b64encode(credential).decode()}"

    def _add_header(
        self,
        headers: Headers,
        authz_header: str,
    ) -> Headers:
        headers = httpx.Headers(headers)
        headers[authz_header] = self._token

        return headers.raw


class AsyncBasicAuth(_BasicAuthBase, AsyncAuth):
    async def arequest(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: AsyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        self._add_header(headers, authz_header)

        return await connection.arequest(
            method,
            url,
            headers=headers.raw,
            stream=stream,
            ext=ext,
        )


class SyncBasicAuth(_BasicAuthBase, SyncAuth):
    def request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers = None,
        stream: SyncByteStream = None,
        ext: typing.Dict = None,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        self._add_header(headers, authz_header)

        return connection.request(method, url, headers=headers.raw, stream=stream, ext=ext)
