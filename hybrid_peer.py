import requests
import threading
import socket
import argparse
import hashlib
import os

# Constants
TRACKER_URL = "http://127.0.0.1:5000"  #Central Tracker Address
DOWNLOAD_FOLDER = "downloads/p2p_share"
LISTEN_PORT = 5001  # Fixed listening port for handshake
BUFFER_SIZE = 8192  # Same chunk size for uniform file division (for future use)

# Ensure download folder exists
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

class Peer:
    def __init__(self, peer_ip, listen_port):
        self.peer_ip = peer_ip
        self.listen_port = listen_port
        self.active_transfers = {}  # To track ongoing transfers
                
    def start_listener(self):
        """Start listening for incoming peer requests (Daemon Thread)."""
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.bind((self.peer_ip, self.listen_port))
        listener_socket.listen(5) 
        print(f"🔄 Peer is listening on {self.peer_ip}:{self.listen_port} for incoming requests...")

        while True:
            client_socket, addr = listener_socket.accept()
            thread = threading.Thread(target=self.handle_peer_request, args=(client_socket, addr), daemon=True)
            thread.start()
    
    def handle_peer_request(self, client_socket, addr):
        """Handles incoming file requests from other peers (TCP)."""
        try:
            file_hash = client_socket.recv(BUFFER_SIZE).decode().strip()

            # Allocate a new port to handle the file transfer
            transfer_port = self.get_available_port()
            client_socket.send(str(transfer_port).encode())
            client_socket.close()

            # Start a separate thread to handle actual file sending
            threading.Thread(
                target=self.start_file_transfer,
                args=(transfer_port, file_hash, addr[0]),
                daemon=True
            ).start()

        except Exception as e:
            print(f"❌ Error in handle_peer_request: {e}")

    
    def start_file_transfer(self, transfer_port, file_hash, peer_ip):
        """Starts a TCP server on a new port to send the requested file."""
        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transfer_socket.bind((self.peer_ip, transfer_port))
        transfer_socket.listen(1)

        print(f"📡 Ready to send file {file_hash} on port {transfer_port}...")

        conn, _ = transfer_socket.accept()

        file_path = os.path.join(DOWNLOAD_FOLDER, file_hash)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    conn.send(chunk)
            print(f"✅ Sent file {file_hash} to {peer_ip}:{transfer_port}")
        else:
            print(f"❌ File {file_hash} not found!")

        conn.close()
        transfer_socket.close()
        
        
    def get_available_port(self):
        """Finds an available port dynamically."""
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.bind((self.peer_ip, 0))
        _, port = temp_socket.getsockname()
        temp_socket.close()
        return port


#############################   Server Section Ends ##############################

##  Peer Registration Section
def register_peer(file_path):
    """Registers the peer with the tracker after computing file hash."""
    file_hash = compute_file_hash(file_path)
    peer_info = {
        "file_hash": file_hash,
        "ip": "127.0.0.1",
        "chunks":["full"],
        "port": LISTEN_PORT
    }
    
    response = requests.post(f"{TRACKER_URL}/register_peer", json=peer_info)
    
    if response.status_code == 200:
        print(f"✅ Successfully registered file '{file_path}' with hash {file_hash}")
    else:
        print(f"❌ Registration failed! {response.text}")

# 🟢 Compute Hash of the file
def compute_file_hash(file_path):
    """Computes SHA-1 hash of the file."""
    hasher = hashlib.sha1()  

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):  # Read in chunks (8KB chunk size) 
            hasher.update(chunk)

    return hasher.hexdigest()  # Return hash as a string


## Client Section
def get_peers(file_hash):
    """Get a list of peers that have the requested file."""
    response = requests.get(f"{TRACKER_URL}/get_peers?file_hash={file_hash}")
    return response.json().get("peers", [])
        

def request_file(peer_ip, file_hash):
    """Sends a TCP request to another peer to download a file."""
    try:
        # Step 1: Send file request (TCP handshake)
        handshake_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        handshake_socket.connect((peer_ip, LISTEN_PORT))

        # Send the file hash as plain text
        handshake_socket.send(file_hash.encode())

        # Receive the dynamic transfer port from the peer
        transfer_port = int(handshake_socket.recv(BUFFER_SIZE).decode())
        handshake_socket.close()

        print(f"🔄 Peer {peer_ip} assigned transfer port {transfer_port}")

        # Step 2: Connect to dynamic port and download the file
        download_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        download_socket.connect((peer_ip, transfer_port))

        file_path = os.path.join(DOWNLOAD_FOLDER, file_hash)
        with open(file_path, "wb") as f:
            while True:
                chunk = download_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)

        print(f"✅ Downloaded {file_hash} from {peer_ip}:{transfer_port}")
        download_socket.close()

    except Exception as e:
        print(f"⚠️ Error requesting file from {peer_ip}:{LISTEN_PORT} - {e}")


def download_file(file_hash):
    """Handles full file download from multiple peers."""

    print(f"✅ File found! Hash: {file_hash}")
    peers = get_peers(file_hash)

    if not peers:
        print("❌ No peers available for this file.")
        return

    print(f"🌐 Found {len(peers)} peers. Starting download...")

    threads = []
    for peer in peers:
        peer_ip = peer["ip"]
        thread = threading.Thread(target=request_file, args=(peer_ip, file_hash))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("🎉 Download completed!")





if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P2P Hybrid File Sharing Node")
    parser.add_argument("--file", help="Path to the file to register")
    parser.add_argument("--file_hash", help="Name of the file to download")
    parser.add_argument("--peer_ip", default="127.0.0.1", help="Peer IP address")
    parser.add_argument("--listen", action="store_true", help="Start peer listener")

    args = parser.parse_args()

    if args.listen:
        peer = Peer(args.peer_ip, LISTEN_PORT)
        peer.start_listener()
    elif args.file:
        register_peer(args.file) ## This is file path
    elif args.file_hash:
        download_file(args.file_hash)
    else:
        print("❌ Invalid usage. Run with --file <file_path> to register or --file_hash <name> to download or --listen")



    # def handle_peer_request(self, client_socket, addr):
    #     """Handles incoming file requests from other peers."""
    #     request_data = client_socket.recv(BUFFER_SIZE).decode()
    #     file_hash = request_data.split(":", 1)
        
    #     # Assign a new dynamic port for transfer
    #     transfer_port = self.get_available_port()

    #     # Inform the requesting peer of the new transfer port
    #     client_socket.send(str(transfer_port).encode())
    #     client_socket.close()

    #     # Start file transfer on the new port
    #     threading.Thread(target=self.start_file_transfer, args=(transfer_port, file_hash, addr[0])).start()

    # def start_file_transfer(self, transfer_port, file_hash, peer_ip):
    #     """Handles the actual file transfer on a new dynamic port (Daemon Thread)."""
    #     transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     transfer_socket.bind((self.peer_ip, transfer_port))
    #     transfer_socket.listen(1)

    #     print(f"📡 Ready to send file {file_hash} on port {transfer_port}...")

    #     conn, _ = transfer_socket.accept()
    #     file_path = os.path.join(DOWNLOAD_FOLDER, file_hash)

    #     if os.path.exists(file_path):
    #         with open(file_path, "rb") as file:
    #             while chunk := file.read(8192):
    #                 conn.send(chunk)
    #         print(f"✅ Sent file {file_hash} to {peer_ip}:{transfer_port}")
    #     else:
    #         print(f"❌ File {file_hash} not found!")

    #     conn.close()
    #     transfer_socket.close()


# def request_file(peer_ip,  file_hash):
#     """Initiates handshake and downloads a file from a peer."""
#     try:
#         # Step 1: Request transfer port from peer
#         handshake_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         handshake_socket.connect((peer_ip, LISTEN_PORT))
#         handshake_socket.send(f"{file_hash}:{LISTEN_PORT}".encode())
#         transfer_port = int(handshake_socket.recv(BUFFER_SIZE).decode())
#         handshake_socket.close()

#         print(f"🔄 Peer {peer_ip} assigned transfer port {transfer_port}")

#         # Step 2: Download file from assigned transfer port
#         download_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         download_socket.connect((peer_ip, transfer_port))
#         file_path = os.path.join(DOWNLOAD_FOLDER, file_hash)

#         with open(file_path, "wb") as file:
#             while chunk := download_socket.recv(BUFFER_SIZE):
#                 file.write(chunk)

#         print(f"✅ Downloaded {file_hash} from {peer_ip}:{transfer_port}")
#         download_socket.close()

#     except Exception as e:
#         print(f"⚠️ Error requesting file from {peer_ip}:{LISTEN_PORT} - {e}")



# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="P2P Hybrid File Sharing Node")
#     parser.add_argument("--peer_ip", default="127.0.0.1", help="Peer IP address")

#     args = parser.parse_args()

#     # Start hybrid peer with listener in background
#     peer = Peer(args.peer_ip, LISTEN_PORT)
#     threading.Thread(target=peer.start_listener, daemon=True).start()

#     # Main interactive menu
#     while True:
#         print("\n🔧 Select an option:")
#         print("1. Register a file")
#         print("2. Download a file")
#         print("3. Exit")

#         choice = input("Enter choice (1/2/3): ").strip()

#         if choice == "1":
#             file_path = input("📁 Enter path to file: ").strip()
#             if os.path.exists(file_path):
#                 register_peer(file_path)
#             else:
#                 print("❌ File does not exist.")
#         # elif choice == "2":
#         #     file_hash = input("🔍 Enter file hash to download: ").strip()
#         #     if file_hash:
#         #         download_file(file_hash)
#         elif choice == "3":
#             print("👋 Exiting.")
#             break
#         else:
#             print("❌ Invalid choice. Try again.")