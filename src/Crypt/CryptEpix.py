import base64
import binascii
import hashlib
import bech32

from collections.abc import Container
from typing import Optional

from util.Electrum import dbl_format

lib_verify_best = "sslcrypto"

from lib import sslcrypto
sslcurve_native = sslcrypto.ecc.get_curve("secp256k1")
sslcurve_fallback = sslcrypto.fallback.ecc.get_curve("secp256k1")
sslcurve = sslcurve_native

# Epix chain configuration
EPIX_PREFIX = "epix"
EPIX_PUBKEY_PREFIX = "epixpub"

def newPrivatekey():  # Return new private key
    return sslcurve.private_to_wif(sslcurve.new_private_key()).decode()


def newSeed():
    return binascii.hexlify(sslcurve.new_private_key()).decode()


def hdPrivatekey(seed, child):
    # Too large child id could cause problems
    privatekey_bin = sslcurve.derive_child(seed.encode(), child % 100000000)
    return sslcurve.private_to_wif(privatekey_bin).decode()


def privatekeyToAddress(privatekey):  # Return Epix address from private key
    try:
        if len(privatekey) == 64:
            privatekey_bin = bytes.fromhex(privatekey)
        else:
            privatekey_bin = sslcurve.wif_to_private(privatekey.encode())
        
        # Get public key from private key
        public_key = sslcurve.private_to_public(privatekey_bin)
        
        # Convert to Epix address using bech32 encoding
        return publicKeyToAddress(public_key)
    except Exception:  # Invalid privatekey
        return False


def publicKeyToAddress(public_key):
    """Convert a public key to an Epix bech32 address"""
    try:
        # Hash the public key (SHA256 + RIPEMD160)
        h = hashlib.sha256(public_key).digest()
        from lib.sslcrypto._ecc import ripemd160
        hash160 = ripemd160(h).digest()
        
        # Convert to bech32 format with 'epix' prefix
        converted = bech32.convertbits(hash160, 8, 5)
        if converted is None:
            return False
            
        address = bech32.bech32_encode(EPIX_PREFIX, converted)
        return address
    except Exception:
        return False


def sign(data: str, privatekey: str) -> str:
    """Sign data with privatekey, return base64 string signature"""
    if privatekey.startswith("23") and len(privatekey) > 52:
        return None  # Old style private key not supported
    return base64.b64encode(sslcurve.sign(
        data.encode(),
        sslcurve.wif_to_private(privatekey.encode()),
        recoverable=True,
        hash=dbl_format
    )).decode()


def get_sign_address_64(data: str, sign: str, lib_verify=None) -> Optional[str]:
    """Returns pubkey/address of signer if any"""
    if not lib_verify:
        lib_verify = lib_verify_best

    if not sign:
        return None

    try:
        publickey = sslcurve.recover(base64.b64decode(sign), data.encode(), hash=dbl_format)
        sign_address = publicKeyToAddress(publickey)
        return sign_address
    except Exception:
        return None


def verify(*args, **kwargs):
    """Default verify, see verify64"""
    return verify64(*args, **kwargs)


def verify64(data: str, addresses: str | Container[str], sign: str, lib_verify=None) -> bool:
    """Verify that sign is a valid signature for data by one of addresses

    Expecting signature to be in base64
    """
    sign_address = get_sign_address_64(data, sign, lib_verify)

    if isinstance(addresses, str):
        return sign_address == addresses
    else:
        return sign_address in addresses


def isValidAddress(addr):
    """Check if provided address is valid Epix bech32 address"""
    try:
        if not addr.startswith(EPIX_PREFIX):
            return False
        
        # Decode bech32 address
        hrp, data = bech32.bech32_decode(addr)
        if hrp != EPIX_PREFIX or data is None:
            return False
            
        # Convert back to check validity
        converted = bech32.convertbits(data, 5, 8, False)
        if converted is None or len(converted) != 20:
            return False
            
        return True
    except Exception:
        return False


def addressToHash160(addr):
    """Convert Epix bech32 address to hash160"""
    try:
        if not isValidAddress(addr):
            return None
            
        hrp, data = bech32.bech32_decode(addr)
        if hrp != EPIX_PREFIX or data is None:
            return None
            
        converted = bech32.convertbits(data, 5, 8, False)
        if converted is None or len(converted) != 20:
            return None
            
        return bytes(converted)
    except Exception:
        return None


def hash160ToAddress(hash160_bytes):
    """Convert hash160 bytes to Epix bech32 address"""
    try:
        if len(hash160_bytes) != 20:
            return None
            
        converted = bech32.convertbits(hash160_bytes, 8, 5)
        if converted is None:
            return None
            
        address = bech32.bech32_encode(EPIX_PREFIX, converted)
        return address
    except Exception:
        return None
