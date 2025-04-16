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
    file_size = data.get("file_size")  # ✅ new line
    peer_ip = request.remote_addr
    chunks = data.get("chunks", [])
    port = data.get("port")

    if not file_hash or not isinstance(chunks, list) or not port:
        return jsonify({"error": "Missing file_hash, port or chunks"}), 400

    with lock:
        # ✅ If this file_hash is new, initialize with file_size and empty peers list
        if file_hash not in file_registry:
            if not file_size:
                return jsonify({"error": "Missing file_size for new file"}), 400  # First time must include it
            file_registry[file_hash] = {
                "file_size": file_size,
                "peers": []
            }

        # ✅ Reference to peers list
        existing_peers = file_registry[file_hash]["peers"]

        # Prevent duplicate registration
        for peer in existing_peers:
            if peer["ip"] == peer_ip and peer["port"] == port:
                peer["chunks"] = chunks  # Update chunks if already exists
                break
        else:
            existing_peers.append({
                "ip": peer_ip,
                "port": port,
                "chunks": chunks
            })

    return jsonify({"message": f"Peer {peer_ip}:{port} registered for file {file_hash}"}), 200

# 📌 Get list of peers and their available chunks for a file
@app.route('/get_peers', methods=['GET'])
def get_peers():
    file_hash = request.args.get("file_hash")

    if not file_hash or file_hash not in file_registry:
        return jsonify({"peers": [], "file_size": 0}), 200

    entry = file_registry[file_hash]
    # entry is expected to be a dict like:
    # {"file_size": 12345, "peers": [{ip: ..., port: ...}, ...]}

    return jsonify({
        "peers": entry["peers"],
        "file_size": entry.get("file_size", 0)
    }), 200


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