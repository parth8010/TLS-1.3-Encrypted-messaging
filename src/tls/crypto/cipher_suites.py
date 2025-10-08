# TLS 1.3 Cipher Suites Implementation
# AES-GCM and ChaCha20-Poly1305 encryption/decryption


import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("TLSCipher")

class CipherSuite:
    
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.sequence_number = 0
        
    def encrypt(self, plaintext, additional_data=b""):
        """Encrypt plaintext with associated data"""
        raise NotImplementedError
        
    def decrypt(self, ciphertext, additional_data=b""):
        """Decrypt ciphertext with associated data"""
        raise NotImplementedError
        
    def update_sequence_number(self):
        """Update sequence number for next record"""
        self.sequence_number += 1
        if self.sequence_number >= (1 << 64):
            # Trigger key update in TLS 1.3
            self.sequence_number = 0


class AESGCM(CipherSuite):
    
    def __init__(self, key, iv):
        super().__init__(key, iv)
        self.nonce_length = 12
        
    def encrypt(self, plaintext, additional_data=b""):

        try:
            # Construct nonce: IV XOR sequence_number
            nonce = self._construct_nonce()
            
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(additional_data)
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Get authentication tag
            auth_tag = encryptor.tag
            
            self.update_sequence_number()
            logger.debug(f"AES-GCM encrypted {len(plaintext)} bytes, tag: {auth_tag.hex()[:16]}...")
            
            return ciphertext, auth_tag
            
        except Exception as e:
            logger.error(f"AES-GCM encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext, auth_tag, additional_data=b""):

        try:
            # Construct nonce: IV XOR sequence_number
            nonce = self._construct_nonce()
            
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(additional_data)
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.update_sequence_number()
            logger.debug(f"AES-GCM decrypted {len(ciphertext)} bytes")
            
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {e}")
            raise
    
    def _construct_nonce(self):
        """Construct nonce for AES-GCM: iv XOR sequence_number"""
        # Convert sequence number to bytes (8 bytes)
        seq_bytes = self.sequence_number.to_bytes(8, byteorder='big')
        # Pad with zeros to match IV length (12 bytes)
        seq_padded = b'\x00' * 4 + seq_bytes
        
        # XOR IV with padded sequence number
        nonce = bytes(a ^ b for a, b in zip(self.iv, seq_padded))
        return nonce


class ChaCha20Poly1305(CipherSuite):
    
    def __init__(self, key, iv):
        super().__init__(key, iv)
        
    def encrypt(self, plaintext, additional_data=b""):

        try:
            # Construct nonce: IV + sequence_number
            nonce = self._construct_nonce()
            
            # Create ChaCha20-Poly1305 cipher
            cipher = Cipher(
                algorithms.ChaCha20(self.key, nonce),
                mode=None,  # ChaCha20 doesn't use a mode
                backend=default_backend()
            )
            
            # In production, use proper ChaCha20-Poly1305 construction
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext)
            
            # Generate auth tag (simplified - in real implementation use Poly1305)
            auth_tag = self._generate_auth_tag(ciphertext, additional_data, nonce)
            
            self.update_sequence_number()
            logger.debug(f"ChaCha20 encrypted {len(plaintext)} bytes")
            
            return ciphertext, auth_tag
            
        except Exception as e:
            logger.error(f"ChaCha20 encryption failed: {e}")
            raise
    
    def decrypt(self, ciphertext, auth_tag, additional_data=b""):

        try:
            # Construct nonce: IV + sequence_number
            nonce = self._construct_nonce()
            
            # Verify auth tag first
            expected_tag = self._generate_auth_tag(ciphertext, additional_data, nonce)
            if auth_tag != expected_tag:
                raise ValueError("Authentication tag verification failed")
            
            # Create ChaCha20 cipher
            cipher = Cipher(
                algorithms.ChaCha20(self.key, nonce),
                mode=None,
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)
            
            self.update_sequence_number()
            logger.debug(f"ChaCha20 decrypted {len(ciphertext)} bytes")
            
            return plaintext
            
        except Exception as e:
            logger.error(f"ChaCha20 decryption failed: {e}")
            raise
    
    def _construct_nonce(self):
        """Construct nonce for ChaCha20: iv[0..11] + sequence_number"""
        seq_bytes = self.sequence_number.to_bytes(4, byteorder='big')
        return self.iv[:12] + seq_bytes
    
    def _generate_auth_tag(self, ciphertext, additional_data, nonce):
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(additional_data)
        h.update(ciphertext)
        h.update(nonce)
        return h.finalize()[:16]  # Truncate to 16 bytes for AEAD tag


class CipherSuiteFactory:
    """ for creating cipher suite instances"""
    
    @staticmethod
    def create_cipher_suite(suite_name, key, iv):

        if suite_name == "TLS_AES_256_GCM_SHA384":
            return AESGCM(key, iv)
        elif suite_name == "TLS_CHACHA20_POLY1305_SHA256":
            return ChaCha20Poly1305(key, iv)
        else:
            raise ValueError(f"Unsupported cipher suite: {suite_name}")
    
    @staticmethod
    def get_key_iv_lengths(suite_name):

        if suite_name == "TLS_AES_256_GCM_SHA384":
            return 32, 12  # AES-256 key, 12-byte IV
        elif suite_name == "TLS_CHACHA20_POLY1305_SHA256":
            return 32, 12  # ChaCha20 key, 12-byte nonce
        else:
            raise ValueError(f"Unsupported cipher suite: {suite_name}")