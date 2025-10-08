
import socket
import threading
import logging
from src.config import ServerConfig
from src.utils.logging import setup_logging
from src.tls.protocol.handshake import TLSHandshake, ClientHello
from src.tls.protocol.record_layer import TLSRecordManager

class TLSServer:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.running = False
        self.clients = {}  # client_id -> client_info
        
        # Setup logging
        setup_logging()
        self.logger = logging.getLogger("TLSServer")
        
        # Load configuration
        self.config = ServerConfig()
        
    def start(self):
        """Start the TLS messaging server"""
        try:
            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            self.running = True
            self.logger.info(f" TLS Messaging Server started on {self.host}:{self.port}")
            self.logger.info("Waiting for incoming connections...")            
            self._accept_connections()
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            self.stop()
    
    def _accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                self.logger.info(f" New connection from {client_address}")                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connection with TLS 1.3"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            # Initialize TLS for this connection
            tls_handshake = TLSHandshake(is_server=True)
            record_manager = TLSRecordManager(is_server=True)
            
            self.logger.info(f" Starting TLS 1.3 handshake with {client_id}")
            
            # Perform TLS handshake
            if self._perform_tls_handshake(client_socket, client_id, tls_handshake, record_manager):
                handshake_keys = tls_handshake.get_handshake_keys(is_server=True)
                record_manager.enable_encryption("TLS_AES_256_GCM_SHA384", handshake_keys)
                
                self.logger.info(f" TLS handshake completed successfully with {client_id}")
                
                # Store client information
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'tls_handshake': tls_handshake,
                    'record_manager': record_manager,
                    'username': None
                }
                
                # Start secure messaging
                self._handle_secure_messages(client_id)
            else:
                self.logger.warning(f" TLS handshake failed for {client_id}")
                client_socket.close()
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
    
    def _perform_tls_handshake(self, client_socket, client_id, tls_handshake, record_manager):
        try:
            # Receive ClientHello
            self.logger.info(f" Waiting for ClientHello from {client_id}")
            client_hello_data = client_socket.recv(4096)
            
            if not client_hello_data:
                self.logger.warning(f"No data received from {client_id}")
                return False            
            server_hello_data, handshake_complete = tls_handshake.process_client_hello(client_hello_data)
            
            if not server_hello_data:
                self.logger.error(f"Failed to process ClientHello from {client_id}")
                return False
            
            # Send ServerHello back to client
            self.logger.info(f" Sending ServerHello to {client_id}")
            client_socket.send(server_hello_data)
            self.logger.info(f" Basic TLS handshake completed with {client_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"TLS handshake failed for {client_id}: {e}")
            return False
    
    def _handle_secure_messages(self, client_id):
        """Handle encrypted messages from client"""
        client_info = self.clients[client_id]
        client_socket = client_info['socket']
        record_manager = client_info['record_manager']
        
        try:
            buffer = b""
            
            while self.running and client_id in self.clients:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data                
                messages, buffer = record_manager.receive_data(buffer)
                
                for msg_type, msg_data in messages:
                    if msg_type == 'application_data':
                        # Decrypted application message
                        message_text = msg_data.decode('utf-8', errors='ignore')
                        self.logger.info(f" Received secure message from {client_id}: {message_text}")
                        
                        # Echo back securely
                        encrypted_response = record_manager.send_application_data(msg_data)
                        client_socket.send(encrypted_response)
                        self.logger.info(f" Sent secure echo to {client_id}")
                        
                    elif msg_type == 'handshake':
                        self.logger.info(f" Received handshake message from {client_id}")
                        # Process further handshake messages if needed
                    elif msg_type == 'alert':
                        self.logger.warning(f" Received alert from {client_id}: {msg_data.hex()}")
                
        except Exception as e:
            self.logger.error(f"Error handling secure messages for {client_id}: {e}")
        finally:
            self._disconnect_client(client_id)
    
    def _disconnect_client(self, client_id):
        if client_id in self.clients:
            client_info = self.clients[client_id]
            client_info['socket'].close()
            del self.clients[client_id]
            self.logger.info(f" Client {client_id} disconnected")
    
    def stop(self):
        self.running = False
        self.logger.info(" Shutting down server...")
        
        # Close all client connections
        for client_id in list(self.clients.keys()):
            self._disconnect_client(client_id)
        
        # Close server socket
        if hasattr(self, 'socket'):
            self.socket.close()
        
        self.logger.info(" Server stopped")

def main():
    """Main server entry point"""
    server = TLSServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.logger.info("Received interrupt signal")
    finally:
        server.stop()

if __name__ == "__main__":
    main()