"""node_server.py
Flask HTTP interface for the blockchain node.
Run:  python node_server.py --port 5000
For learning only. Do not use this server on the public internet.
"""

import argparse

from flask import Flask, jsonify, request

from blockchain_core import Blockchain, Wallet

app = Flask(__name__)

# Three test wallets. Private keys stay inside the server.
wallets = {name: Wallet(name) for name in ("민수", "지우", "서연")}

# Starting balances for the lesson
chain = Blockchain({
    wallets["민수"].address: 20,
    wallets["지우"].address: 10,
    wallets["서연"].address: 0,
}, difficulty=3)


# Show Korean text normally in JSON answers
app.json.ensure_ascii = False


@app.get("/")
def home():
    return jsonify({
        "service": "Educational Blockchain Node",
        "routes": ["/wallets", "/balances", "/chain"],
    })


@app.get("/wallets")
def get_wallets():
    # Only addresses. Never private keys.
    return jsonify({name: w.address for name, w in wallets.items()})


@app.get("/chain")
def get_chain():
    return jsonify({
        "length": len(chain.chain),
        "chain": chain.chain,
        "pending_count": len(chain.pending),
        "valid": chain.valid_chain(),
    })


@app.get("/balances")
def get_balances():
    confirmed, _ = chain.confirmed_state()
    pending, _ = chain.pending_state()
    return jsonify({
        "confirmed": {n: confirmed[w.address] for n, w in wallets.items()},
        "pending": {n: pending[w.address] for n, w in wallets.items()},
    })


@app.post("/demo/transfer")
def demo_transfer():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {
            "sender", "receiver", "amount"}:
        return jsonify({"accepted": False, "error": "필수 필드 오류"}), 400

    # Check names and amount
    if data["sender"] not in wallets or data["receiver"] not in wallets:
        return jsonify({"accepted": False, "error": "미등록 이름"}), 400
    if type(data["amount"]) is not int or data["amount"] <= 0:
        return jsonify({"accepted": False, "error": "금액 오류"}), 400

    sender = wallets[data["sender"]]
    receiver = wallets[data["receiver"]]

    # Next nonce for this sender (pending transactions included)
    _, nonces = chain.pending_state()
    nonce = nonces[sender.address]

    # The demo server signs with the sender's private key.
    # In a real wallet, the client signs, not the server.
    tx = sender.create_transaction(receiver.address, data["amount"], nonce)

    ok, message = chain.submit(tx)
    if not ok:
        return jsonify({"accepted": False, "error": message}), 400
    return jsonify({
        "accepted": True,
        "message": message,
        "nonce": nonce,
        "pending_count": len(chain.pending),
    }), 201


@app.post("/mine")
def mine():
    block = chain.mine()
    if block is None:
        return jsonify({"error": "대기 거래 없음"}), 400
    return jsonify({
        "block_index": block["index"],
        "hash": block["hash"],
        "nonce": block["nonce"],
        "valid": chain.valid_chain(),
    }), 201


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host="127.0.0.1", port=args.port, debug=False)
