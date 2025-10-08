
# Handles key derivation according to TLS 1.3 


import logging
from .foundation import hkdf_extract, hkdf_expand_label

logger = logging.getLogger("TLSKeySchedule")

class TLSKeySchedule:
    def __init__(self):
        self.early_secret = None
        self.handshake_secret = None
        self.master_secret = None
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.client_application_traffic_secret = None
        self.server_application_traffic_secret = None
        
    def derive_handshake_secrets(self, shared_secret, client_hello_random, server_hello_random):

        logger.debug("Deriving handshake secrets...")
        
        # Derive early secret (with default PSK of zeros)
        self.early_secret = hkdf_extract(salt=b'\x00' * 32, ikm=b'\x00' * 32)
        
        # Derive derived secret for handshake
        derived_secret = hkdf_expand_label(
            secret=self.early_secret,
            label="derived",
            context=b"",
            length=32
        )
        
        # Extract handshake secret from shared secret
        self.handshake_secret = hkdf_extract(
            salt=derived_secret,
            ikm=shared_secret
        )
        
        # Derive client handshake traffic secret
        self.client_handshake_traffic_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="c hs traffic",
            context=self._get_handshake_context(client_hello_random, server_hello_random),
            length=32
        )
        
        # Derive server handshake traffic secret
        self.server_handshake_traffic_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="s hs traffic",
            context=self._get_handshake_context(client_hello_random, server_hello_random),
            length=32
        )
        
        logger.debug("Handshake secrets derived successfully")
        
    def derive_application_secrets(self, handshake_context):

        logger.debug("Deriving application secrets...")
        
        # Derive derived secret for master secret
        derived_secret = hkdf_expand_label(
            secret=self.handshake_secret,
            label="derived",
            context=b"",
            length=32
        )
        
        # Extract master secret
        self.master_secret = hkdf_extract(
            salt=derived_secret,
            ikm=b'\x00' * 32  # Empty IKMs for master secret
        )
        
        # Derive client application traffic secret
        self.client_application_traffic_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="c ap traffic",
            context=handshake_context,
            length=32
        )
        
        # Derive server application traffic secret
        self.server_application_traffic_secret = hkdf_expand_label(
            secret=self.master_secret,
            label="s ap traffic",
            context=handshake_context,
            length=32
        )
        
        logger.debug("Application secrets derived successfully")
    
    def derive_traffic_keys(self, traffic_secret, key_length=16, iv_length=12):

        key = hkdf_expand_label(
            secret=traffic_secret,
            label="key",
            context=b"",
            length=key_length
        )
        
        iv = hkdf_expand_label(
            secret=traffic_secret,
            label="iv",
            context=b"",
            length=iv_length
        )
        
        return {
            'key': key,
            'iv': iv
        }
    
    def _get_handshake_context(self, client_hello_random, server_hello_random):
        """ Create handshake context from ClientHello and ServerHello"""
        return client_hello_random + server_hello_random
    
    def get_client_handshake_keys(self, key_length=16, iv_length=12):
        """Get client handshake encryption keys"""
        return self.derive_traffic_keys(
            self.client_handshake_traffic_secret,
            key_length,
            iv_length
        )
    
    def get_server_handshake_keys(self, key_length=16, iv_length=12):
        """Get server handshake encryption keys"""
        return self.derive_traffic_keys(
            self.server_handshake_traffic_secret,
            key_length,
            iv_length
        )
    
    def get_client_application_keys(self, key_length=16, iv_length=12):
        """Get client application encryption keys"""
        return self.derive_traffic_keys(
            self.client_application_traffic_secret,
            key_length,
            iv_length
        )
    
    def get_server_application_keys(self, key_length=16, iv_length=12):
        """Get server application encryption keys"""
        return self.derive_traffic_keys(
            self.server_application_traffic_secret,
            key_length,
            iv_length
        )
    
    def update_application_traffic_secret(self, is_client=True):
        """
        Update traffic secret for key rotation (TLS 1.3 feature)
        Args:
            is_client: Whether to update client or server secret
        """
        if is_client:
            self.client_application_traffic_secret = hkdf_expand_label(
                secret=self.client_application_traffic_secret,
                label="traffic upd",
                context=b"",
                length=32
            )
        else:
            self.server_application_traffic_secret = hkdf_expand_label(
                secret=self.server_application_traffic_secret,
                label="traffic upd",
                context=b"",
                length=32
            )