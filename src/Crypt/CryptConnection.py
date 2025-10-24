import sys
import logging
import os
import ssl
import hashlib
import random
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from Config import config
from util import helper


class CryptConnectionManager:
    def __init__(self):
        if config.openssl_bin_file:
            self.openssl_bin = config.openssl_bin_file
        elif sys.platform.startswith("win"):
            # Handle PyInstaller bundled paths (_internal directory on Windows)
            if hasattr(sys, '_MEIPASS'):
                # Running as frozen PyInstaller executable
                self.openssl_bin = os.path.join(sys._MEIPASS, "tools", "openssl", "openssl.exe")
            else:
                # Running from source
                self.openssl_bin = "tools\\openssl\\openssl.exe"
        elif config.dist_type.startswith("bundle_linux"):
            self.openssl_bin = "../runtime/bin/openssl"
        elif config.is_android:
            # assuming termux, TODO: android build, android-nix
            self.openssl_bin = '/data/data/com.termux/files/usr/bin/openssl'
        else:
            self.openssl_bin = "openssl"

        self.context_client = None
        self.context_server = None

        self.openssl_conf_template = "src/lib/openssl/openssl.cnf"
        self.openssl_conf = config.private_dir / "openssl.cnf"

        self.openssl_env = {
            "OPENSSL_CONF": str(self.openssl_conf),
            "RANDFILE": str(config.private_dir / "openssl-rand.tmp")
        }

        self.crypt_supported = []  # Supported cryptos

        self.cacert_pem = config.private_dir / "cacert-rsa.pem"
        self.cakey_pem = config.private_dir / "cakey-rsa.pem"
        self.cert_pem = config.private_dir / "cert-rsa.pem"
        self.cert_csr = config.private_dir / "cert-rsa.csr"
        self.key_pem = config.private_dir / "key-rsa.pem"

        self.log = logging.getLogger("CryptConnectionManager")
        self.log.debug("Version: %s" % ssl.OPENSSL_VERSION)

        self.fakedomains = [
            "yahoo.com", "amazon.com", "live.com", "microsoft.com", "mail.ru", "csdn.net", "bing.com",
            "amazon.co.jp", "office.com", "imdb.com", "msn.com", "samsung.com", "huawei.com", "ztedevices.com",
            "godaddy.com", "w3.org", "gravatar.com", "creativecommons.org", "hatena.ne.jp",
            "adobe.com", "opera.com", "apache.org", "rambler.ru", "one.com", "nationalgeographic.com",
            "networksolutions.com", "php.net", "python.org", "phoca.cz", "debian.org", "ubuntu.com",
            "nazwa.pl", "symantec.com"
        ]

    def createSslContexts(self):
        if self.context_server and self.context_client:
            return False
        ciphers = "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA256:AES256-SHA:"
        ciphers += "!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"

        if hasattr(ssl, "PROTOCOL_TLS"):
            protocol = ssl.PROTOCOL_TLS
        else:
            protocol = ssl.PROTOCOL_TLSv1_2
        self.context_client = ssl.SSLContext(protocol)
        self.context_client.check_hostname = False
        self.context_client.verify_mode = ssl.CERT_NONE

        self.context_server = ssl.SSLContext(protocol)
        self.context_server.load_cert_chain(self.cert_pem, self.key_pem)

        for ctx in (self.context_client, self.context_server):
            ctx.set_ciphers(ciphers)
            ctx.options |= ssl.OP_NO_COMPRESSION
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                ctx.set_npn_protocols(["h2", "http/1.1"])
            except Exception:
                pass

    # Select crypt that supported by both sides
    # Return: Name of the crypto
    def selectCrypt(self, client_supported):
        for crypt in self.crypt_supported:
            if crypt in client_supported:
                return crypt
        return False

    # Wrap socket for crypt
    # Return: wrapped socket
    def wrapSocket(self, sock, crypt, server=False, cert_pin=None):
        if crypt == "tls-rsa":
            if server:
                sock_wrapped = self.context_server.wrap_socket(sock, server_side=True)
            else:
                sock_wrapped = self.context_client.wrap_socket(sock, server_hostname=random.choice(self.fakedomains))
            if cert_pin:
                cert_hash = hashlib.sha256(sock_wrapped.getpeercert(True)).hexdigest()
                if cert_hash != cert_pin:
                    raise Exception("Socket certificate does not match (%s != %s)" % (cert_hash, cert_pin))
            return sock_wrapped
        else:
            return sock

    def removeCerts(self):
        if config.keep_ssl_cert:
            return False
        for file_name in ["cert-rsa.pem", "key-rsa.pem", "cacert-rsa.pem", "cakey-rsa.pem", "cacert-rsa.srl", "cert-rsa.csr", "openssl-rand.tmp"]:
            file_path = config.data_dir / file_name
            if file_path.is_file():
                os.unlink(file_path)

    # Load and create cert files is necessary
    def loadCerts(self):
        if config.disable_encryption:
            return False

        if self.createSslRsaCert() and "tls-rsa" not in self.crypt_supported:
            self.crypt_supported.append("tls-rsa")

    # Try to create RSA server cert + sign for connection encryption
    # Return: True on success
    def createSslRsaCert(self):
        casubjects = [
            ("US", "Amazon", "Server CA 1B", "Amazon"),
            ("US", "Let's Encrypt", "", "Let's Encrypt Authority X3"),
            ("US", "DigiCert Inc", "www.digicert.com", "DigiCert SHA2 High Assurance Server CA"),
            ("GB", "COMODO CA Limited", "", "COMODO RSA Domain Validation Secure Server CA")
        ]
        self.openssl_env['CN'] = random.choice(self.fakedomains)

        if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
            self.createSslContexts()
            return True  # Files already exist

        try:
            self.log.debug("Generating RSA CAcert and CAkey PEM files using cryptography library...")

            # Generate CA private key
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate CA certificate
            ca_subject = random.choice(casubjects)
            ca_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, ca_subject[0]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_subject[1]),
            ])
            if ca_subject[2]:
                ca_name = x509.Name(list(ca_name) + [
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ca_subject[2]),
                ])
            ca_name = x509.Name(list(ca_name) + [
                x509.NameAttribute(NameOID.COMMON_NAME, ca_subject[3]),
            ])

            now = datetime.now(timezone.utc)
            ca_cert = x509.CertificateBuilder().subject_name(
                ca_name
            ).issuer_name(
                ca_name
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now + timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).sign(ca_key, hashes.SHA256())

            # Save CA certificate and key
            with open(self.cacert_pem, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(self.cakey_pem, "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            self.log.debug("Generated CA certificate and key")

            # Generate server private key
            server_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate server certificate signing request
            server_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.openssl_env['CN']),
            ])

            csr = x509.CertificateSigningRequestBuilder().subject_name(
                server_name
            ).sign(server_key, hashes.SHA256())

            # Save CSR
            with open(self.cert_csr, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

            # Sign the CSR with CA certificate
            now = datetime.now(timezone.utc)
            server_cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now + timedelta(days=730)
            ).sign(ca_key, hashes.SHA256())

            # Save server certificate and key
            with open(self.cert_pem, "wb") as f:
                f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            with open(self.key_pem, "wb") as f:
                f.write(server_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            self.log.debug("Generated server certificate and key")

            if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
                self.createSslContexts()

                # Remove no longer necessary files
                try:
                    if os.path.isfile(self.openssl_conf):
                        os.unlink(self.openssl_conf)
                    if os.path.isfile(self.cacert_pem):
                        os.unlink(self.cacert_pem)
                    if os.path.isfile(self.cakey_pem):
                        os.unlink(self.cakey_pem)
                    if os.path.isfile(self.cert_csr):
                        os.unlink(self.cert_csr)
                except Exception as e:
                    self.log.warning("Failed to clean up temporary files: %s" % e)

                return True
            else:
                self.log.error("RSA SSL cert generation failed, cert or key files not exist.")
                return False

        except Exception as e:
            self.log.error("RSA SSL cert generation failed: %s" % e)
            return False


manager = CryptConnectionManager()
