"""
Configuration for TLS Messaging App
"""

class ServerConfig:
    def __init__(self):
        self.host = 'localhost'
        self.port = 8443
        self.max_clients = 100
        self.cert_file = 'certificates/server.crt'
        self.key_file = 'certificates/server.key'
        self.cipher_suite = 'TLS_AES_256_GCM_SHA384'

class ClientConfig:
    def __init__(self):
        self.server_host = 'localhost'
        self.server_port = 8443
        self.ca_cert_file = 'certificates/ca.crt'
        self.cipher_suite = 'TLS_AES_256_GCM_SHA384'