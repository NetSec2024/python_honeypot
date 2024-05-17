import socket
import sys
import threading
import paramiko
import logging

# Configurazione del logging
logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Caricamento delle chiavi server per Paramiko
host_key = paramiko.RSAKey(filename='test_rsa.key')

class Server(paramiko.ServerInterface):
    def __init__(self, source_addr=None):
        self.event = threading.Event()
        self.source_addr = source_addr

    # boh
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logging.info(f"[{self.source_addr[0]}:{self.source_addr[1]}] Login attempted (username, password)=({username}, {password})")
        return paramiko.AUTH_FAILED


def handle_connection(client_sock, client_addr):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = Server(source_addr=client_addr)

    # SSH server init
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            raise Exception("No channel")
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        return

    while True:
        try:
            data = channel.recv(1024) # data received from the client
            if not data:
                break
        except Exception as e:
            logging.error(f"Channel error: {e}")
            break
    channel.close()

def main():
    server_ip = '0.0.0.0'
    server_port = 2222

    try:
        # Socket creation
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((server_ip, server_port))
        server_socket.listen(100) # max number of queued connections
        logging.info(f"Honeypot SSH started on {server_ip}:{server_port}")
    except Exception as e:
        logging.error(f"Bind failed: {e}")
        sys.exit(1)

    while True:
        client_socket, client_address = server_socket.accept() # accept a connection
        logging.info(f"Connection from {client_address}")
        threading.Thread(target=handle_connection, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    main()
