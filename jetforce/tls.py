import base64
import datetime
import os
import tempfile
import typing

import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from twisted.internet.ssl import CertificateOptions, TLSVersion
from twisted.python.randbytes import secureRandom

COMMON_NAME = x509.NameOID.COMMON_NAME


def inspect_certificate(cert: x509) -> dict:
    """
    Extract useful fields from a x509 client certificate object.
    """
    name_attrs = cert.subject.get_attributes_for_oid(COMMON_NAME)
    common_name = name_attrs[0].value if name_attrs else ""

    fingerprint_bytes = cert.fingerprint(hashes.SHA256())
    fingerprint = base64.urlsafe_b64encode(fingerprint_bytes).decode()

    not_before = cert.not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = cert.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")

    serial_number = cert.serial_number

    data = {
        "common_name": common_name,
        "fingerprint": fingerprint,
        "not_before": not_before,
        "not_after": not_after,
        "serial_number": serial_number,
    }
    return data


def generate_ad_hoc_certificate(hostname: str) -> typing.Tuple[str, str]:
    """
    Utility function to generate an ad-hoc self-signed SSL certificate.
    """
    certfile = os.path.join(tempfile.gettempdir(), f"{hostname}.crt")
    keyfile = os.path.join(tempfile.gettempdir(), f"{hostname}.key")

    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        backend = default_backend()

        private_key = rsa.generate_private_key(65537, 2048, backend)
        with open(keyfile, "wb") as fp:
            # noinspection PyTypeChecker
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fp.write(key_data)

        common_name = x509.NameAttribute(COMMON_NAME, hostname)
        subject_name = x509.Name([common_name])
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=365)
        certificate = x509.CertificateBuilder(
            subject_name=subject_name,
            issuer_name=subject_name,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
        )
        certificate = certificate.sign(private_key, hashes.SHA256(), backend)
        with open(certfile, "wb") as fp:
            # noinspection PyTypeChecker
            cert_data = certificate.public_bytes(serialization.Encoding.PEM)
            fp.write(cert_data)

    return certfile, keyfile


class GeminiCertificateOptions(CertificateOptions):
    """
    CertificateOptions is a factory function that twisted provides to do all of
    the confusing PyOpenSSL configuration for you. Unfortunately, their built-in
    class doesn't support the verify callback and some other options required
    for implementing TOFU pinning, so I had to subclass and add custom behavior.

    References:
        https://twistedmatrix.com/documents/16.1.1/core/howto/ssl.html
        https://github.com/urllib3/urllib3/blob/master/src/urllib3/util/ssl_.py
        https://github.com/twisted/twisted/blob/trunk/src/twisted/internet/_sslverify.py
    """

    def verify_callback(
        self,
        conn: OpenSSL.SSL.Connection,
        cert: OpenSSL.crypto.X509,
        errno: int,
        depth: int,
        preverify_ok: int,
    ) -> bool:
        """
        Callback used by OpenSSL for client certificate verification.

        preverify_ok will contain the verification result that OpenSSL has
        determined based on the server's CA trust store.

        Return preverify_ok to cede control to the underlying library.
        Return True to allow unverified, self-signed client certificates.

        This callback may be invoked multiple times during the TLS handshake.
        If at any point OpenSSL returns a preverify_ok value of zero, we should
        mark the certificate as not trusted.
        """
        if not hasattr(conn, "authorised"):
            conn.authorised = preverify_ok
        else:
            conn.authorised *= preverify_ok

        return True

    def proto_select_callback(
        self, conn: OpenSSL.SSL.Connection, protocols: typing.List[bytes]
    ) -> bytes:
        """
        Callback used by OpenSSL for ALPN support.

        Return the first matching protocol in our list of acceptable values.
        This is not currently being used but I may want to add support later.
        """
        for p in self._acceptableProtocols:
            if p in protocols:
                return p
        else:
            return b""

    def sni_callback(self, conn: OpenSSL.SSL.Connection) -> None:
        """
        Callback used by OpenSSL for SNI support.

        We can inspect the servername requested by the client using
        conn.get_servername(), and attach an appropriate context using
        conn.set_context(new_context). This is not currently being used but
        I want to add support in the future.
        """
        pass

    def __init__(
        self,
        certfile: str,
        keyfile: typing.Optional[str] = None,
        cafile: typing.Optional[str] = None,
        capath: typing.Optional[str] = None,
    ) -> None:

        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.capath = capath

        super().__init__(
            raiseMinimumTo=TLSVersion.TLSv1_2,
            requireCertificate=False,
            fixBrokenPeers=True,
        )

    def _makeContext(self) -> OpenSSL.SSL.Context:
        """
        Most of this code is copied directly from the parent class method.
        """
        ctx = self._contextFactory(self.method)
        ctx.set_options(self._options)
        ctx.set_mode(self._mode)

        ctx.use_certificate_file(self.certfile)
        ctx.use_privatekey_file(self.keyfile or self.certfile)
        for extraCert in self.extraCertChain:
            ctx.add_extra_chain_cert(extraCert)
        # Sanity check
        ctx.check_privatekey()

        if self.cafile or self.capath:
            ctx.load_verify_locations(self.cafile, self.capath)

        verify_flags = OpenSSL.SSL.VERIFY_PEER
        if self.requireCertificate:
            verify_flags |= OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT
        if self.verifyOnce:
            verify_flags |= OpenSSL.SSL.VERIFY_CLIENT_ONCE

        ctx.set_verify(verify_flags, self.verify_callback)
        if self.verifyDepth is not None:
            ctx.set_verify_depth(self.verifyDepth)

        if self.enableSessions:
            session_name = secureRandom(32)
            ctx.set_session_id(session_name)

        ctx.set_cipher_list(self._cipherString.encode("ascii"))

        self._ecChooser.configureECDHCurve(ctx)

        if self._acceptableProtocols:
            ctx.set_alpn_select_callback(self.proto_select_callback)
            ctx.set_alpn_protos(self._acceptableProtocols)

        ctx.set_tlsext_servername_callback(self.sni_callback)

        return ctx
