import socket
import sys
import threading
import paramiko
import logging

# Logging configuration
logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# server's authentication key
host_key = paramiko.RSAKey(filename='test_rsa.key')

# ---------------- REDEFINE PARAMIKO'S INTERFACE -------------------

class Server(paramiko.ServerInterface):
    def __init__(self, source_addr=None):
        self.event = threading.Event()          # Event object that allows one thread to signal another thread that some condition has been met
        self.source_addr = source_addr

    def check_auth_password(self, username, password):
        logging.info(f"[{self.source_addr[0]}:{self.source_addr[1]}] Login attempted (username, password)=({username}, {password})")
        return paramiko.AUTH_FAILED             # Always return AUTH_FAILED to simulate a failed login

# ---------------------- CONNECTION HANDLING ----------------------

# Function that 
def handle_connection(client_sock, client_addr):
    transport = paramiko.Transport(client_sock) # | Sockets -> transport layer | SSH -> application layer |
    transport.add_server_key(host_key)          # Server's authentication key
    server = Server(source_addr=client_addr)    # There will be a server object for each connection

    # SSH server init
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)          # Accept a connection with a timeout of 20 seconds
        if channel is None:
            raise Exception("No channel")
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        return

    while True:
        try:
            data = channel.recv(1024)           # data received from the client
            if not data:
                break
        except Exception as e:
            logging.error(f"Channel error: {e}")
            break
    channel.close()


# ---------------------- MAIN ----------------------

def main():
    server_ip = '0.0.0.0' # listen to all interfaces
    server_port = 2222
    max_queued_connections = 100

    try:
        # Socket creation
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      # AF_INET: IPv4, SOCK_STREAM: TCP
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        server_socket.bind((server_ip, server_port))                           # bind the socket to the address
        server_socket.listen(max_queued_connections)                           # max number of queued connections
        logging.info(f"Server socket listening on {server_ip}:{server_port}")  # log the start of the honeypot
    except Exception as e:
        logging.error(f"Bind failed: {e}")
        sys.exit(1)

    while True:
        client_socket, client_address = server_socket.accept()                  # accept a connection
        logging.info(f"Connection from {client_address}")                       # log the connection
        threading.Thread(target=handle_connection, args=(client_socket, client_address)).start() # handle the connection in a new thread

# -----------------------------------------------------

if __name__ == "__main__":
    main()

# -----------------------------------------------------
