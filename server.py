from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

# Dictionary to store file_hash → {peer_ip: [chunk_list]}
file_registry = {}

# Lock for thread safety
lock = threading.Lock()

# 📌 Register a peer and its chunk info
@app.route('/register_peer', methods=['POST'])
def register_peer():
    data = request.json
    file_hash = data.get("file_hash")
    peer_ip = request.remote_addr  # Get IP of requesting peer
    chunks = data.get("chunks", [])  # List of chunks the peer has

    if not file_hash or not isinstance(chunks, list):
        return jsonify({"error": "Missing file_hash or chunks"}), 400

    with lock:
        if file_hash not in file_registry:
            file_registry[file_hash] = {}
        file_registry[file_hash][peer_ip] = chunks  # Store chunks for this peer

    return jsonify({"message": f"Peer {peer_ip} registered with {len(chunks)} chunks for file {file_hash}"}), 200

# 📌 Get list of peers and their available chunks for a file
@app.route('/get_peers', methods=['GET'])
def get_peers():
    file_hash = request.args.get("file_hash")

    if not file_hash or file_hash not in file_registry:
        return jsonify({"peers": {}}), 200  # Return empty if file not found

    return jsonify({"peers": file_registry[file_hash]}), 200

# 📌 Remove a peer (when it disconnects)
@app.route('/remove_peer', methods=['DELETE'])
def remove_peer():
    data = request.json
    file_hash = data.get("file_hash")
    peer_ip = request.remote_addr

    if not file_hash or file_hash not in file_registry:
        return jsonify({"message": "File hash not found"}), 404

    with lock:
        if peer_ip in file_registry[file_hash]:
            del file_registry[file_hash][peer_ip]  # Remove peer
            if not file_registry[file_hash]:  # If no peers left, remove file entry
                del file_registry[file_hash]

    return jsonify({"message": f"Peer {peer_ip} removed for file {file_hash}"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)