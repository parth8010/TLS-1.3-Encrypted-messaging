
import socket
import threading
import logging
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.logging import setup_logging
from src.config import ClientConfig
from src.tls.protocol.handshake import TLSHandshake
from src.tls.protocol.record_layer import TLSRecordManager
from src.utils.logging import setup_logging
from src.tls.protocol.handshake import TLSHandshake, ClientHello
from src.tls.protocol.record_layer import TLSRecordManager

class TLSClient:
    def __init__(self, server_host='localhost', server_port=8443):
        self.server_host = server_host
        self.server_port = server_port
        self.connected = False
        self.socket = None
        self.tls_handshake = None
        self.record_manager = None  
        setup_logging()
        self.logger = logging.getLogger("TLSClient")        
        self.config = ClientConfig()
        
    def connect(self):
        """Connect to the TLS messaging server with TLS 1.3"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.logger.info(f"Connecting to server {self.server_host}:{self.server_port}...")
            
            # Connect to server
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            self.logger.info("Connected to server!")
            
            # Initialize TLS
            self.tls_handshake = TLSHandshake(is_server=False)
            self.record_manager = TLSRecordManager(is_server=False)
            
            # Perform TLS handshake
            self.logger.info("Starting TLS 1.3 handshake with server...")
            if self._perform_tls_handshake():
                self.logger.info("TLS handshake successful! Secure connection established.")
                # Start message handling
                self._start_message_handling()
            else:
                self.logger.error("TLS handshake failed!")
                self.disconnect()
                
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            self.disconnect()
    
    def _perform_tls_handshake(self):
        try:
            # Create and send ClientHello
            client_hello = self.tls_handshake.create_client_hello()
            self.logger.info("Sending ClientHello to server...")
            self.socket.send(client_hello)
            
            # Receive ServerHello response
            self.logger.info("Waiting for ServerHello from server...")
            server_response = self.socket.recv(4096)
            
            if not server_response:
                self.logger.error("No response from server")
                return False
            
            # Process ServerHello
            handshake_complete = self.tls_handshake.process_server_hello(server_response)
            
            # Enable encryption after handshake
            handshake_keys = self.tls_handshake.get_handshake_keys(is_server=False)
            self.record_manager.enable_encryption("TLS_AES_256_GCM_SHA384", handshake_keys)
            self.logger.info("Encryption enabled for handshake")
            
            return True
                
        except Exception as e:
            self.logger.error(f"TLS handshake failed: {e}")
            return False
    
    def _start_message_handling(self):
        # Start thread for receiving messages
        receive_thread = threading.Thread(target=self._receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Main thread for sending messages
        self._send_messages()
    
    def _receive_messages(self):
        buffer = b""
        
        try:
            while self.connected:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                buffer += data                
                try:
                    messages, buffer = self.record_manager.receive_data(buffer)
                    
                    for msg_type, msg_data in messages:
                        if msg_type == 'application_data':
                            # This is decrypted text!
                            message_text = msg_data.decode('utf-8')
                            print(f"\n Server: {message_text}")
                            print("You: ", end="", flush=True)
                        else:
                            print(f"\n Received {msg_type} message")
                            print("You: ", end="", flush=True)
                except Exception as e:
                    # If record processing fails, show raw data
                    print(f"\n Received {len(data)} encrypted bytes")
                    print(f"Hex: {data.hex()[:50]}...")
                    print("You: ", end="", flush=True)
                
        except Exception as e:
            if self.connected:
                self.logger.error(f"Error receiving messages: {e}")
        finally:
            self.disconnect()
    
    def _send_messages(self):
        """Send messages to server"""
        try:
            print("\n TLS Messaging Client Started!")
            print("Type your messages and press Enter to send.")
            print("Type 'quit' to exit.\n")
            print("You: ", end="", flush=True)
            
            while self.connected:
                # Get user input
                message = input()
                
                if message.lower() == 'quit':
                    break
                
                encrypted_data = self.record_manager.send_application_data(message.encode())
                self.socket.send(encrypted_data)
                self.logger.info(f" Sent encrypted message: {len(encrypted_data)} bytes")
                
                print("You: ", end="", flush=True)
                
        except Exception as e:
            if self.connected:
                self.logger.error(f"Error sending messages: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self):
        self.connected = False
        if self.socket:
            self.socket.close()
            self.socket = None
        self.logger.info(" Disconnected from server")

def main():
    """Main client entry point"""
    client = TLSClient()
    
    try:
        client.connect()
    except KeyboardInterrupt:
        client.logger.info("Received interrupt signal")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()