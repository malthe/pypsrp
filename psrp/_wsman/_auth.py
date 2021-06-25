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
    ByteStream,
    SyncByteStream,
    SyncHTTPTransport,
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


class _AuthBase:
    """Base authentication handler for the WSMan transports."""

    SUPPORTS_ENCRYPTION = False

    def handle_request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: SyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        return connection.handle_request(method, url, headers, stream, extensions)

    async def handle_async_request(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: AsyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        return await connection.handle_async_request(method, url, headers, stream, extensions)

    def reset(self):
        pass


class NoAuth(_AuthBase):
    """Authentication handler that is no-op and doesn't provide any authentication on HTTP requests."""


class NegotiateAuth(_AuthBase):

    SUPPORTS_ENCRYPTION = True

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
        valid_protocols = ["kerberos", "negotiate", "ntlm", "credssp"]
        if protocol not in valid_protocols:
            raise ValueError(f"{type(self).__name__} protocol only supports {', '.join(valid_protocols)}")

        self.protocol = protocol.lower()

        self._auth_header = {
            "negotiate": "Negotiate",
            "ntlm": "Negotiate",
            "kerberos": "Kerberos",
            "credssp": "CredSSP",
        }[self.protocol]
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
        """Whether the authentication process is complete."""
        return self.__complete or (self._context and self._context.complete)

    def handle_request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: SyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        if not self._complete:
            self._context = self._build_context(connection, url[1])

            status_code = 500
            resp_headers = httpx.Headers()
            resp_stream = ByteStream(b"")

            send_headers, send_stream = self._wrap(headers, stream.read())
            in_token = None

            while not self._context.complete:
                out_token = self._context.step(in_token)
                if not out_token:
                    break

                self._add_header(send_headers, out_token, authz_header)
                status_code, resp_headers, resp_stream, extensions = connection.handle_request(
                    method, url, send_headers.raw, send_stream, extensions
                )
                headers, resp_stream = self._unwrap(resp_headers, resp_stream.read())

                # If we didn't encrypt then the response from the auth phase
                # contains our actual response. Also pass along any errors back.
                in_token = self._get_header_token(resp_headers, auths_header)
                if not in_token:
                    break

            if not self._encrypt or status_code != 200:
                return status_code, resp_headers.raw, resp_stream, extensions

        headers, stream = self._wrap(headers, stream.read())
        status_code, headers, stream, extensions = connection.request(method, url, headers.raw, stream, extensions)
        headers, stream = self._unwrap(headers, stream.read())

        return status_code, headers.raw, stream, extensions

    async def handle_async_request(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: AsyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        if not self._complete:
            self._context = await _async_wrap(self._build_context, connection, url[1])

            status_code = 500
            resp_headers = httpx.Headers()
            resp_stream = ByteStream(b"")

            send_headers, send_stream = self._wrap(headers, stream)
            in_token = None

            while not self._context.complete:
                out_token = await _async_wrap(self._context.step, in_token)
                if not out_token:
                    break

                self._add_header(send_headers, out_token, authz_header)
                status_code, resp_headers, resp_stream, extensions = await connection.handle_async_request(
                    method, url, send_headers.raw, send_stream, extensions
                )
                resp_headers, resp_stream = self._unwrap(resp_headers, await resp_stream.aread())

                in_token = self._get_header_token(resp_headers, auths_header)
                if not in_token:
                    break

            # If we didn't encrypt then the response from the auth phase
            # contains our actual response. Also pass along any errors back.
            if not self._encrypt or status_code != 200:
                return status_code, resp_headers.raw, resp_stream, extensions

        headers, stream = self._wrap(headers, await stream.aread())
        status_code, headers, stream, extensions = await connection.handle_async_request(
            method, url, headers.raw, stream, extensions
        )
        headers, stream = self._unwrap(headers, await stream.aread())

        return status_code, headers.raw, stream, extensions

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
        data: typing.Optional[bytes] = None,
    ) -> typing.Tuple[httpx.Headers, ByteStream]:
        temp_headers = httpx.Headers(headers)

        if self._encrypt and data:
            protocol = {
                "kerberos": "Kerberos",
                "credssp": "CredSSP",
            }.get(self.protocol, "SPNEGO")

            enc_data, content_type = encrypt_wsman(
                bytearray(data),
                temp_headers["Content-Type"],
                f"application/HTTP-{protocol}-session-encrypted",
                self._context,
            )
            temp_headers["Content-Type"] = content_type
            temp_headers["Content-Length"] = str(len(enc_data))

            data = enc_data

        elif not data:
            temp_headers["Content-Length"] = "0"
            data = b""

        return temp_headers, ByteStream(data)

    def _unwrap(
        self,
        headers: Headers,
        data: bytes,
    ) -> typing.Tuple[httpx.Headers, ByteStream]:
        temp_headers = httpx.Headers(headers)

        content_type = temp_headers.get("Content-Type", "")

        # A proxy will have these content types but cannot do the encryption so
        # we must also check for self._encrypt.
        if self._encrypt and (
            content_type.startswith("multipart/encrypted;") or content_type.startswith("multipart/x-multi-encrypted;")
        ):
            data, content_type = decrypt_wsman(bytes(data), content_type, self._context)
            temp_headers["Content-Length"] = str(len(data))
            temp_headers["Content-Type"] = content_type

        return temp_headers, ByteStream(bytes(data))


class BasicAuth(_AuthBase):
    def __init__(
        self,
        username: str,
        password: str,
    ):
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

    def handle_request(
        self,
        connection: SyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: SyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, SyncByteStream, typing.Dict]:
        headers = self._add_header(headers, authz_header)

        return connection.handle_request(method, url, headers, stream, extensions)

    async def handle_async_request(
        self,
        connection: AsyncHTTPTransport,
        method: bytes,
        url: URL,
        headers: Headers,
        stream: AsyncByteStream,
        extensions: typing.Dict,
        auths_header: str = WWW_AUTHS,
        authz_header: str = WWW_AUTHZ,
    ) -> typing.Tuple[int, Headers, AsyncByteStream, typing.Dict]:
        headers = self._add_header(headers, authz_header)

        return await connection.handle_async_request(method, url, headers, stream, extensions)


AuthHandler = typing.TypeVar("AuthHandler", bound=_AuthBase)
