import requests
import socket
import json
import threading
import os
from concurrent.futures import ThreadPoolExecutor
import hashlib
import argparse

# Tracker URL
TRACKER_URL = "http://127.0.0.1:5000"

# Get current peer IP (for local testing)
def get_local_ip():    
    return socket.gethostbyname(socket.gethostname())

# Compute Hash of the file
def compute_file_hash(file_path):
    #Computes SHA-1 hash of the file.
    hasher = hashlib.sha1()  

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):  # Read in chunks (8KB chunk size) 
            
            #Larger Size → Fewer disk reads, but uses more RAM.
            #Smaller Size → Uses less RAM, but increases file read operations.
            hasher.update(chunk)

    return hasher.hexdigest()  # Return hash as a string



# Register peer with the tracker
def register_peer(file_hash, chunks):
    peer_ip = get_local_ip()
    data = {
        "file_hash": file_hash,
        "chunks": chunks
    }
    response = requests.post(f"{TRACKER_URL}/register_peer", json=data)
    print("🔹 Register Response:", response.json())

# Get peers
def get_peers(file_hash):
    response = requests.get(f"{TRACKER_URL}/get_peers", params={"file_hash": file_hash})
    if response.status_code == 200:
        peers = response.json()["peers"]
        print(f"🔹 Peers with file '{file_hash}':", json.dumps(peers, indent=4))
        return peers
    else:
        print("❌ File not found on tracker")
        return None
    
if __name__ == "__main__":
    file_path = "testfile.txt"  # 🔄 Replace with your actual file
    file_hash = compute_file_hash(file_path)
    
    chunks = [0, 1, 2]  # 🔧 Simulated chunk list — replace with real chunking logic if needed
    
    register_peer(file_hash, chunks)  # Register with tracker
    get_peers(file_hash)              # Fetch list of peers


