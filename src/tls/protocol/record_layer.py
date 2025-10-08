
import logging
import struct
from enum import Enum
from typing import Optional, Tuple

from ..crypto.cipher_suites import CipherSuiteFactory

logger = logging.getLogger("TLSRecord")

class ContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class TLSRecord:
    """TLS Record Layer Protocol"""
    
    def __init__(self):
        self.sequence_number = 0
        self.encryption_keys = None
        self.cipher_suite = None
        self.encryption_enabled = False
        
    def enable_encryption(self, cipher_suite_name: str, keys: dict, is_server: bool):
 
        self.cipher_suite = CipherSuiteFactory.create_cipher_suite(
            cipher_suite_name, 
            keys['key'], 
            keys['iv']
        )
        self.encryption_enabled = True
        logger.info(f"Encryption enabled with {cipher_suite_name}")
    
    def wrap_handshake(self, handshake_data: bytes) -> bytes:
        """
        Wrap handshake data in TLS record
        Args:
            handshake_data: Raw handshake message data
        Returns: TLS record bytes
        """
        return self._create_record(ContentType.HANDSHAKE, handshake_data)
    
    def wrap_application_data(self, app_data: bytes) -> bytes:
 
        return self._create_record(ContentType.APPLICATION_DATA, app_data)
    
    def unwrap_record(self, record_data: bytes) -> Tuple[ContentType, bytes]:

        try:
            # Parse record header
            if len(record_data) < 5:
                raise ValueError("Record too short")
                
            content_type = ContentType(record_data[0])
            version = struct.unpack('>H', record_data[1:3])[0]
            length = struct.unpack('>H', record_data[3:5])[0]
            
            # Check length
            if len(record_data) < 5 + length:
                raise ValueError(f"Record incomplete: expected {length}, got {len(record_data) - 5}")
            
            # Extract fragment
            fragment = record_data[5:5+length]
            
            # return raw data without decryption
            # implement decryption once handshake is fully working
            logger.debug(f"Unwrapped record: type={content_type.name}, length={len(fragment)}")
            return content_type, fragment
            
        except struct.error as e:
            logger.error(f"Struct error parsing record: {e}")
            # If it's not a valid TLS record, treat it as application data
            return ContentType.APPLICATION_DATA, record_data
        except Exception as e:
            logger.error(f"Failed to unwrap record: {e}")
            # Fallback: treat as application data
            return ContentType.APPLICATION_DATA, record_data
    
    def _create_record(self, content_type: ContentType, data: bytes) -> bytes:

        encrypted_data = data
        
        # Build record
        record = (
            struct.pack('>B', content_type.value) +  # Content type
            struct.pack('>H', 0x0301) +              # TLS 1.0 legacy version
            struct.pack('>H', len(encrypted_data)) + # Length
            encrypted_data                           # Fragment
        )
        
        logger.debug(f"Created record: type={content_type.name}, length={len(encrypted_data)}")
        return record

class TLSRecordManager:
    """Manages TLS record layer for client/server"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.record_layer = TLSRecord()
        self.handshake_buffer = b""
        
    def send_handshake(self, handshake_data: bytes) -> bytes:

        return self.record_layer.wrap_handshake(handshake_data)
    
    def send_application_data(self, app_data: bytes) -> bytes:

        return self.record_layer.wrap_application_data(app_data)
    
    def receive_data(self, data: bytes) -> Tuple[list, bytes]:

        messages = []
        remaining_data = data
        
        while len(remaining_data) >= 5:  # Minimum record header size
            try:
                if len(remaining_data) < 5:
                    break
                    
                length = struct.unpack('>H', remaining_data[3:5])[0]
                total_record_length = 5 + length
                
                # Check if we have complete record
                if len(remaining_data) < total_record_length:
                    break  
                
                # Process complete record
                record_data = remaining_data[:total_record_length]
                content_type, decrypted_data = self.record_layer.unwrap_record(record_data)
                
                if content_type == ContentType.HANDSHAKE:
                    self.handshake_buffer += decrypted_data
                    messages.extend(self._process_handshake_buffer())
                elif content_type == ContentType.APPLICATION_DATA:
                    messages.append(('application_data', decrypted_data))
                elif content_type == ContentType.ALERT:
                    messages.append(('alert', decrypted_data))
                
                # Move to next record
                remaining_data = remaining_data[total_record_length:]
                
            except struct.error as e:
                logger.error(f"Struct error: {e}, treating as application data")
                # Treat remaining data as application data
                messages.append(('application_data', remaining_data))
                remaining_data = b""
                break
            except Exception as e:
                logger.error(f"Error processing record: {e}")
                break
        
        return messages, remaining_data
    
    def _process_handshake_buffer(self) -> list:

        messages = []
        
        while len(self.handshake_buffer) >= 4:  
            try:
                # Peek at handshake message length
                msg_length = struct.unpack('>I', b'\x00' + self.handshake_buffer[1:4])[0]
                total_msg_length = 4 + msg_length
                
                # Check if we have complete message
                if len(self.handshake_buffer) < total_msg_length:
                    break 
                    
                # Extract complete message
                message_data = self.handshake_buffer[:total_msg_length]
                msg_type = message_data[0]
                messages.append(('handshake', message_data))
                
                self.handshake_buffer = self.handshake_buffer[total_msg_length:]
            except struct.error:
                break
        
        return messages
    
    def enable_encryption(self, cipher_suite_name: str, keys: dict):
        """Enable encryption on the record layer"""
        self.record_layer.enable_encryption(cipher_suite_name, keys, self.is_server)