
import logging
import struct
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ..crypto.foundation import generate_ephemeral_key, compute_shared_secret, generate_random_bytes
from ..crypto.key_schedule import TLSKeySchedule
from ..crypto.cipher_suites import CipherSuiteFactory

logger = logging.getLogger("TLSHandshake")

class HandshakeType(Enum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24

class TLSVersion(Enum):
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

class CipherSuites(Enum):
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303

class HandshakeMessage:
    
    def __init__(self, msg_type: HandshakeType):
        self.msg_type = msg_type
        
    def serialize(self) -> bytes:
        raise NotImplementedError
        
    @classmethod
    def deserialize(cls, data: bytes):
        """Deserialize message from bytes"""
        raise NotImplementedError


class ClientHello(HandshakeMessage):
    
    def __init__(self):
        super().__init__(HandshakeType.CLIENT_HELLO)
        self.version = TLSVersion.TLS_1_3
        self.random = generate_random_bytes(32)
        self.session_id = b""  # Empty for TLS 1.3
        self.cipher_suites = [CipherSuites.TLS_AES_256_GCM_SHA384]
        self.compression_methods = [0]  # Null compression
        self.extensions = {}
        
        # Generate key share for ECDHE
        self.private_key, self.public_key = generate_ephemeral_key()
        self.extensions['key_share'] = self.public_key
        self.extensions['supported_versions'] = bytes([0x03, 0x04])  # TLS 1.3
        
    def serialize(self) -> bytes:
        """Serialize ClientHello to bytes"""
        # Handshake header
        header = struct.pack('>B', self.msg_type.value)
        random_data = self.random
        session_id = bytes([len(self.session_id)]) + self.session_id
        cipher_suites_data = b''.join([cs.value.to_bytes(2, 'big') for cs in self.cipher_suites])
        cipher_suites = len(cipher_suites_data).to_bytes(2, 'big') + cipher_suites_data
        compression = bytes([len(self.compression_methods)]) + bytes(self.compression_methods)
        extensions_data = self._serialize_extensions()
        extensions = len(extensions_data).to_bytes(2, 'big') + extensions_data
        
        # Message body
        body = (
            self.version.value.to_bytes(2, 'big') +
            random_data +
            session_id +
            cipher_suites +
            compression +
            extensions
        )
        
        # Full message with length
        message = header + len(body).to_bytes(3, 'big') + body
        return message
    
    def _serialize_extensions(self) -> bytes:
        """Serialize extensions to bytes"""
        extensions_data = b''
        
        # Supported versions extension
        if 'supported_versions' in self.extensions:
            ext_data = self.extensions['supported_versions']
            extensions_data += struct.pack('>HH', 43, len(ext_data))  # supported_versions = 43
            extensions_data += ext_data
        
        # Key share extension
        if 'key_share' in self.extensions:
            key_share = self.extensions['key_share']
            # KeyShareEntry: NamedGroup + key_exchange
            key_entry = struct.pack('>HH', 0x001D, len(key_share))  # x25519 = 0x001D
            key_entry += key_share
            extensions_data += struct.pack('>HH', 51, len(key_entry))  # key_share = 51
            extensions_data += key_entry
            
        return extensions_data
    
    @classmethod
    def deserialize(cls, data: bytes):
        """Deserialize ClientHello from bytes"""
        hello = cls()
        return hello


class ServerHello(HandshakeMessage):    
    def __init__(self, client_hello: ClientHello):
        super().__init__(HandshakeType.SERVER_HELLO)
        self.version = TLSVersion.TLS_1_3
        self.random = generate_random_bytes(32)
        self.session_id = b""  # Empty for TLS 1.3
        self.cipher_suite = CipherSuites.TLS_AES_256_GCM_SHA384
        self.compression_method = 0
        self.extensions = {}
        
        # Generate server key share for ECDHE
        self.private_key, self.public_key = generate_ephemeral_key()
        self.extensions['key_share'] = self.public_key
        
        # Store client hello for reference
        self.client_hello = client_hello
        
    def serialize(self) -> bytes:
        """Serialize ServerHello to bytes"""
        # Handshake header
        header = struct.pack('>B', self.msg_type.value)
        
        # Message body
        body = (
            self.version.value.to_bytes(2, 'big') +
            self.random +
            bytes([len(self.session_id)]) + self.session_id +
            self.cipher_suite.value.to_bytes(2, 'big') +
            bytes([self.compression_method])
        )
        
        extensions_data = self._serialize_extensions()
        body += len(extensions_data).to_bytes(2, 'big') + extensions_data
        message = header + len(body).to_bytes(3, 'big') + body
        return message
    
    def _serialize_extensions(self) -> bytes:
        """Serialize extensions to bytes"""
        extensions_data = b''
        
        # Key share extension
        if 'key_share' in self.extensions:
            key_share = self.extensions['key_share']
            # KeyShareEntry: NamedGroup + key_exchange
            key_entry = struct.pack('>HH', 0x001D, len(key_share))  # x25519 = 0x001D
            key_entry += key_share
            extensions_data += struct.pack('>HH', 51, len(key_entry))  # key_share = 51
            extensions_data += key_entry
            
        return extensions_data


class Finished(HandshakeMessage):
    """Finished message for TLS 1.3"""
    
    def __init__(self, verify_data: bytes):
        super().__init__(HandshakeType.FINISHED)
        self.verify_data = verify_data
        
    def serialize(self) -> bytes:
        """Serialize Finished to bytes"""
        header = struct.pack('>B', self.msg_type.value)
        body = self.verify_data
        message = header + len(body).to_bytes(3, 'big') + body
        return message


class TLSHandshake:
    """Main TLS handshake state machine"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.state = "INIT"
        self.key_schedule = TLSKeySchedule()
        self.client_hello = None
        self.server_hello = None
        self.shared_secret = None
        
    def process_client_hello(self, data: bytes) -> Tuple[Optional[bytes], bool]:

        if not self.is_server:
            raise RuntimeError("ClientHello processing only on server side")
            
        logger.info("Processing ClientHello...")
        
        # Parse ClientHello (simplified)
        self.client_hello = ClientHello.deserialize(data)
        
        # Create ServerHello response
        self.server_hello = ServerHello(self.client_hello)
        
        # Compute shared secret
        self.shared_secret = compute_shared_secret(
            self.server_hello.private_key,
            self.client_hello.extensions['key_share']
        )
        
        # Derive handshake secrets
        self.key_schedule.derive_handshake_secrets(
            self.shared_secret,
            self.client_hello.random,
            self.server_hello.random
        )
        
        logger.info("ClientHello processed, shared secret derived")
        self.state = "SERVER_HELLO_SENT"
        
        # Return ServerHello as response
        return self.server_hello.serialize(), False
    
    def process_server_hello(self, data: bytes) -> bool:

        if self.is_server:
            raise RuntimeError("ServerHello processing only on client side")
            
        logger.info("Processing ServerHello...")
        
        # Parse ServerHello
        self.server_hello = ServerHello(None)
        
        # Compute shared secret
        self.shared_secret = compute_shared_secret(
            self.client_hello.private_key,
            self.server_hello.extensions['key_share']
        )
        
        # Derive handshake secrets
        self.key_schedule.derive_handshake_secrets(
            self.shared_secret,
            self.client_hello.random,
            self.server_hello.random
        )
        
        logger.info("ServerHello processed, shared secret derived")
        self.state = "HANDSHAKE_KEYS_DERIVED"
        
        return False
    
    def create_client_hello(self) -> bytes:
        """Create ClientHello message (client side)"""
        if self.is_server:
            raise RuntimeError("ClientHello creation only on client side")
            
        logger.info("Creating ClientHello...")
        self.client_hello = ClientHello()
        self.state = "CLIENT_HELLO_SENT"
        return self.client_hello.serialize()
    
    def get_handshake_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for handshake phase"""
        if is_server:
            return self.key_schedule.get_server_handshake_keys()
        else:
            return self.key_schedule.get_client_handshake_keys()
    
    def get_application_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for application phase"""
        if is_server:
            return self.key_schedule.get_server_application_keys()
        else:
            return self.key_schedule.get_client_application_keys()