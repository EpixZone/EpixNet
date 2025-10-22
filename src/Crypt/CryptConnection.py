import sys
import logging
import os
import ssl
import hashlib
import random

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
            "/C=US/O=Amazon/OU=Server CA 1B/CN=Amazon",
            "/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3",
            "/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA",
            "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Domain Validation Secure Server CA"
        ]
        self.openssl_env['CN'] = random.choice(self.fakedomains)

        if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
            self.createSslContexts()
            return True  # Files already exits

        import subprocess

        # Prepare entropy file for Windows
        randfile_path = config.private_dir / "openssl-rand.tmp"
        try:
            # Generate entropy data and write it to the RANDFILE
            with open(randfile_path, 'wb') as f:
                # Write 2048 bytes of random data to seed the entropy pool
                f.write(os.urandom(2048))
            self.log.debug("Generated entropy file at %s" % randfile_path)
        except Exception as e:
            self.log.warning("Failed to generate entropy file: %s" % e)

        # Replace variables in config template
        conf_template = open(self.openssl_conf_template).read()
        conf_template = conf_template.replace("$ENV::CN", self.openssl_env['CN'])
        open(self.openssl_conf, "w").write(conf_template)

        # Generate CAcert and CAkey
        # Note: Don't use -config and -rand on macOS/LibreSSL as they cause issues
        cmd = [
            self.openssl_bin, "req", "-new", "-newkey", "rsa:2048", "-days", "3650",
            "-nodes", "-x509",
            "-subj", random.choice(casubjects),
            "-keyout", str(self.cakey_pem),
            "-out", str(self.cacert_pem),
            "-batch"
        ]
        # Add -rand parameter on Windows to explicitly provide entropy source
        if sys.platform.startswith("win"):
            cmd.extend(["-rand", str(randfile_path)])
        self.log.debug("Generating RSA CAcert and CAkey PEM files...")
        self.log.debug("Running: %s" % " ".join(cmd))
        proc = subprocess.Popen(
            cmd, stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE, env=self.openssl_env
        )
        back = proc.stdout.read().strip().decode(errors="replace").replace("\r", "")
        proc.wait()

        if not (os.path.isfile(self.cacert_pem) and os.path.isfile(self.cakey_pem)):
            self.log.error("RSA ECC SSL CAcert generation failed, CAcert or CAkey files not exist. (%s)" % back)
            return False
        else:
            self.log.debug("Result: %s" % back)

        # Generate certificate key and signing request
        # Note: Don't use -config and -rand on macOS/LibreSSL as they cause issues
        cmd = [
            self.openssl_bin, "req", "-new", "-newkey", "rsa:2048",
            "-keyout", str(self.key_pem),
            "-out", str(self.cert_csr),
            "-subj", "/CN=" + self.openssl_env['CN'],
            "-sha256", "-nodes", "-batch"
        ]
        # Add -rand parameter on Windows to explicitly provide entropy source
        if sys.platform.startswith("win"):
            cmd.extend(["-rand", str(randfile_path)])
        self.log.debug("Generating certificate key and signing request...")
        proc = subprocess.Popen(
            cmd, stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE, env=self.openssl_env
        )
        back = proc.stdout.read().strip().decode(errors="replace").replace("\r", "")
        proc.wait()
        self.log.debug("Running: %s\n%s" % (" ".join(cmd), back))

        # Sign request and generate certificate
        # Note: Don't use -rand on macOS/LibreSSL as it causes issues
        cmd = [
            self.openssl_bin, "x509", "-req",
            "-in", str(self.cert_csr),
            "-CA", str(self.cacert_pem),
            "-CAkey", str(self.cakey_pem),
            "-set_serial", "01",
            "-out", str(self.cert_pem),
            "-days", "730", "-sha256"
        ]
        # Add -rand parameter on Windows to explicitly provide entropy source
        if sys.platform.startswith("win"):
            cmd.extend(["-rand", str(randfile_path)])
        self.log.debug("Generating RSA cert...")
        proc = subprocess.Popen(
            cmd, stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE, env=self.openssl_env
        )
        back = proc.stdout.read().strip().decode(errors="replace").replace("\r", "")
        proc.wait()
        self.log.debug("Running: %s\n%s" % (" ".join(cmd), back))

        if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
            self.createSslContexts()

            # Remove no longer necessary files
            os.unlink(self.openssl_conf)
            os.unlink(self.cacert_pem)
            os.unlink(self.cakey_pem)
            os.unlink(self.cert_csr)

            return True
        else:
            self.log.error("RSA ECC SSL cert generation failed, cert or key files not exist.")


manager = CryptConnectionManager()
