
import os
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Run: pip install cryptography")


def generate_ephemeral_key():    # Generates ephemeral key pair for ECDHE key exchange (X25519)
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required. Install with: pip install cryptography")
    
    # Generates X25519 private key
    private_key = x25519.X25519PrivateKey.generate()
    
    # Gets public key and serialize to bytes
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_key, public_key_bytes


def generate_random_bytes(length=32):

    return os.urandom(length)


def compute_shared_secret(private_key, peer_public_key_bytes):

    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    # Reconstruct peer's public key from bytes
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    
    # Compute shared secret
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def hkdf_extract(salt, ikm):

    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    # If no salt, use zeros of hash length
    if salt is None:
        salt = b'\x00' * hashes.SHA256().digest_size
    
    # HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    hmac = hashes.Hash(hashes.SHA256())
    hmac.update(salt)
    hmac.update(ikm)
    return hmac.finalize()


def hkdf_expand(prk, info, length):

    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(prk)


def hkdf_expand_label(secret, label, context, length):

    # TLS 1.3 HKDF label format
    hkdf_label = (
        length.to_bytes(2, byteorder='big') +           # Length
        bytes([len(b'tls13 ' + label.encode())]) +     # Label length
        b'tls13 ' + label.encode() +                   # Label
        bytes([len(context)]) +                        # Context length
        context                                         # Context
    )
    
    return hkdf_expand(secret, hkdf_label, length)


def derive_early_secrets(psk=None):

    if psk is None:
        # Default PSK of zeros
        psk = b'\x00' * 32
    
    # Early secret = HKDF-Extract(0, PSK)
    early_secret = hkdf_extract(salt=b'\x00' * 32, ikm=psk)
    return early_secret