import requests
import threading
import socket
import argparse
import hashlib
import os
import shutil

# Constants
TRACKER_URL = "http://127.0.0.1:5000"  #Central Tracker Address
DOWNLOAD_FOLDER = "../downloads/p2p_share"
LISTEN_PORT = 5003  # Fixed listening port for handshake
BUFFER_SIZE = 8192  # Same chunk size for uniform file division (for future use)

# Ensure download folder exists
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

class Peer:
    def __init__(self, my_ip, listen_port):
        self.my_ip = my_ip
        self.listen_port = listen_port
        self.active_transfers = {}  # To track ongoing transfers
                
    def start_listener(self):
        """Start listening for incoming peer requests (Daemon Thread)."""
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.bind((self.my_ip, self.listen_port))  #here (my_ip,listen_port) i will listen , if any client comes with file request
        listener_socket.listen(5) 
        print(f"🔄 Peer is listening on {self.my_ip}:{self.listen_port} for incoming requests...")

        while True:
            client_socket, addr = listener_socket.accept()
            thread = threading.Thread(target=self.handle_peer_request, args=(client_socket, addr), daemon=True)  #if any client comes we process it by creating a new thread
            thread.start()
    
    def handle_peer_request(self, client_socket, addr):
        """Handles incoming file requests from other peers (TCP)."""
        try:
            # Receive file hash and byte range request from the client
            request_data = client_socket.recv(BUFFER_SIZE).decode().strip()
            file_hash, start_byte, end_byte = request_data.split("|")  # Parse file_hash, start_byte, and end_byte
            start_byte, end_byte = int(start_byte), int(end_byte)

            # Allocate a new port to handle the file transfer
            transfer_port = self.get_available_port()
            client_socket.send(str(transfer_port).encode())  # Send the port to client to initiate transfer
            client_socket.close()

            # Start a separate thread to handle the file sending for the requested range
            threading.Thread(
                target=self.start_file_transfer,
                args=(transfer_port, file_hash, start_byte, end_byte, addr[0]),  # Pass start and end byte range
                daemon=True
            ).start()

        except Exception as e:
            print(f"❌ Error in handle_peer_request: {e}")


    def start_file_transfer(self, transfer_port, file_hash, start_byte, end_byte, peer_ip):
        """Starts a TCP server on a new port to send the requested chunk of the file."""
        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transfer_socket.bind((self.my_ip, transfer_port))  # Bind to the transfer port
        transfer_socket.listen(1)

        print(f"📡 Ready to send file chunk {start_byte}-{end_byte} for {file_hash} on port {transfer_port}...")

        conn, _ = transfer_socket.accept()  # Wait for client connection

        file_path = os.path.join(DOWNLOAD_FOLDER, file_hash)  # Locate the file to send

        if os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                f.seek(start_byte)  # Move to the start byte of the chunk
                bytes_to_send = end_byte - start_byte  # Calculate how many bytes to send

                while bytes_to_send > 0:
                    chunk = f.read(min(BUFFER_SIZE, bytes_to_send))  # Read chunk of the file
                    if not chunk:
                        break
                    conn.send(chunk)  # Send the chunk to the peer
                    bytes_to_send -= len(chunk)  # Decrease remaining bytes to send
                print(f"✅ Sent file chunk {start_byte}-{end_byte} from {self.my_ip}:{transfer_port}")
        else:
            print(f"❌ File with hash {file_hash} not found in {DOWNLOAD_FOLDER}")

        conn.close()
        transfer_socket.close()
        
    def get_available_port(self):
        """Finds an available port dynamically."""
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.bind((self.my_ip, 0))
        _, port = temp_socket.getsockname()
        temp_socket.close()
        return port


#############################   Server Section Ends ##############################

##  Peer Registration Section
def register_peer(file_path):
    """Registers the peer with the tracker after computing file hash and copying the file to P2P folder."""
    # Step 1: Compute hash of the original file
    file_hash = compute_file_hash(file_path)

    # Step 2: Copy the file into the P2P download folder using the hash as filename
    dest_path = os.path.join(DOWNLOAD_FOLDER, file_hash)

    if not os.path.exists(dest_path):
        try:
            shutil.copy(file_path, dest_path)
            print(f"📁 Copied file to shared folder as {file_hash}")
        except Exception as e:
            print(f"❌ Error copying file to shared folder: {e}")
            return

    # ✅ Step 2.5: Get file size
    file_size = os.path.getsize(file_path)

    # Step 3: Register with tracker (over HTTP)
    peer_info = {
        "file_hash": file_hash,
        "file_size": file_size,  # ✅ Include file size here
        "ip": "127.0.0.1",
        "chunks": ["full"],
        "port": LISTEN_PORT
    }

    try:
        response = requests.post(f"{TRACKER_URL}/register_peer", json=peer_info)

        if response.status_code == 200:
            print(f"✅ Successfully registered file '{file_path}' with hash {file_hash}")
        else:
            print(f"❌ Registration failed! {response.text}")
    except Exception as e:
        print(f"❌ Tracker registration error: {e}")


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
    try:
        response = requests.get(f"{TRACKER_URL}/get_peers", params={"file_hash": file_hash})  # ✅ Use params
        if response.status_code == 200:
            data = response.json()
            return data["peers"], int(data["file_size"])  # ✅ cast file_size to int
        else:
            print("❌ Tracker returned an error.")
            return [], 0
    except Exception as e:
        print(f"❌ Error contacting tracker: {e}")
        return [], 0

def request_file(peer_ip, peer_port, file_hash, start_byte, end_byte):
    """Requests a specific chunk of the file from a peer."""
    try:
        # Step 1: Send file request (TCP handshake)
        handshake_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        handshake_socket.connect((peer_ip, peer_port))  # Connection to peer

        # Send the file hash and byte range request
        request_data = f"{file_hash}|{start_byte}|{end_byte}"
        handshake_socket.send(request_data.encode())  # Send file hash and byte range

        # Receive the dynamic transfer port from the peer
        transfer_port = int(handshake_socket.recv(BUFFER_SIZE).decode())  # Get the dynamic transfer port
        handshake_socket.close()

        print(f"🔄 Peer {peer_ip} assigned transfer port {transfer_port}")

        # Step 2: Connect to dynamic port and download the chunk
        download_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        download_socket.connect((peer_ip, transfer_port))

        file_path = os.path.join(DOWNLOAD_FOLDER, file_hash + '_received')  # Path to save downloaded file
        with open(file_path, "r+b") as f:  # Open the file in append mode
            f.seek(start_byte)  # Move pointer to start byte of the chunk
            while True:
                chunk = download_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                f.write(chunk)  # Write the chunk to the file

        print(f"✅ Downloaded chunk {start_byte}-{end_byte} from {peer_ip}:{transfer_port}")
        download_socket.close()

    except Exception as e:
        print(f"⚠️ Error in getting file from {peer_ip}:{transfer_port} - {e}")

def download_file(file_hash):
    """Handles full file download from multiple peers in chunks."""
    print(f"✅ File found! Hash: {file_hash}")
    peers, file_size = get_peers(file_hash)  # ⚡ get both peers and file_size

    if not peers:
        print("❌ No peers available for this file.")
        return

    print(f"🌐 Found {len(peers)} peers. Starting download...")
    # 📂 Pre-create the empty file
    file_path = os.path.join(DOWNLOAD_FOLDER, file_hash + '_received')
    with open(file_path, "wb") as f:
        f.truncate(file_size)
    print(f"📄 Pre-created file of size {file_size} bytes.")

    # 🔥 Start downloading parts
    num_peers = len(peers)
    chunk_size = file_size // num_peers

    threads = []

    for i, peer in enumerate(peers):
        peer_ip = peer["ip"]
        peer_port = peer["port"]

        start_byte = i * chunk_size
        end_byte = (i + 1) * chunk_size if i < num_peers - 1 else file_size  # Last peer adjusts

        thread = threading.Thread(target=request_file, args=(peer_ip, peer_port, file_hash, start_byte, end_byte))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("🎉 Download completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P2P Hybrid File Sharing Node")
    parser.add_argument("--peer_ip", default="127.0.0.1", help="Peer IP address")

    args = parser.parse_args()

    # Start hybrid peer with listener in background
    peer = Peer(args.peer_ip, LISTEN_PORT)
    threading.Thread(target=peer.start_listener, daemon=True).start()

    # Main interactive menu
    while True:
        print("\n🔧 Select an option:")
        print("1. Register a file")
        print("2. Download a file")
        print("3. Exit")

        choice = input("Enter choice (1/2/3): ").strip()

        if choice == "1":
            file_path = input("📁 Enter path to file: ").strip()
            if os.path.exists(file_path):
                register_peer(file_path)
            else:
                print("❌ File does not exist.")
        elif choice == "2":
            file_hash = input("🔍 Enter file hash to download: ").strip()
            if file_hash:
                download_file(file_hash)
        elif choice == "3":
            print("👋 Exiting.")
            break
        else:
            print("❌ Invalid choice. Try again.")