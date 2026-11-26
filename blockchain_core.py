"""blockchain_core.py
Core blockchain logic for the Week 10 lab.
Wallet, signing, transaction checks, mining (proof of work), chain validation.
This is for learning only. It is not a real cryptocurrency.
"""

import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ---------------------------------------------------------------
# STEP 2. Same JSON bytes every time (needed for signing and hashing)
# ---------------------------------------------------------------
def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value):
    return hashlib.sha256(canonical(value)).hexdigest()


# ---------------------------------------------------------------
# STEP 3. Address from public key
# ---------------------------------------------------------------
def public_bytes(key):
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def address_of(key):
    # Learning rule: SHA-256 of the public key, first 40 hex characters
    return hashlib.sha256(public_bytes(key)).hexdigest()[:40]


# ---------------------------------------------------------------
# STEP 4 and 5. Wallet: keys, address, signed transaction
# ---------------------------------------------------------------
class Wallet:
    def __init__(self, name):
        self.name = name
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.address = address_of(self.public_key)

    def create_transaction(self, receiver, amount, nonce):
        # This is the body that gets signed
        tx = {
            "sender": self.address,
            "receiver": receiver,
            "amount": amount,
            "nonce": nonce,
        }
        signature = self.private_key.sign(
            canonical(tx), ec.ECDSA(hashes.SHA256())
        )
        # Send the public key and signature with the transaction.
        # The private key is never included.
        return {
            **tx,
            "public_key": public_bytes(self.public_key).hex(),
            "signature": signature.hex(),
        }


# ---------------------------------------------------------------
# STEP 6. Signature check
# ---------------------------------------------------------------
def verify_signature(tx):
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(tx["public_key"])
        )
        # The public key must match the sender address
        if address_of(pub) != tx["sender"]:
            return False
        body = {k: tx[k] for k in ("sender", "receiver", "amount", "nonce")}
        pub.verify(
            bytes.fromhex(tx["signature"]),
            canonical(body),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


# ---------------------------------------------------------------
# STEP 7 to 15. Blockchain
# ---------------------------------------------------------------
class Blockchain:
    def __init__(self, initial, difficulty=3):
        self.difficulty = difficulty
        self.initial = dict(initial)  # starting balances
        self.chain = []               # confirmed blocks
        self.pending = []             # transactions not mined yet

        genesis = {
            "index": 0,
            "timestamp": 0,
            "transactions": [],
            "previous_hash": "0" * 64,
            "nonce": 0,
            "difficulty": 0,
        }
        genesis["hash"] = sha256_hex(genesis)
        self.chain.append(genesis)

    # STEP 8. Balances and nonces from confirmed blocks only
    def confirmed_state(self):
        balances = dict(self.initial)
        nonces = {a: 0 for a in self.initial}
        for block in self.chain[1:]:  # skip genesis
            for tx in block["transactions"]:
                balances[tx["sender"]] -= tx["amount"]
                balances[tx["receiver"]] += tx["amount"]
                nonces[tx["sender"]] += 1
        return balances, nonces

    # STEP 9. Confirmed state + pending transactions
    def pending_state(self):
        balances, nonces = self.confirmed_state()
        for tx in self.pending:
            balances[tx["sender"]] -= tx["amount"]
            balances[tx["receiver"]] += tx["amount"]
            nonces[tx["sender"]] += 1
        return balances, nonces

    # STEP 10 and 11. Rules for a transaction.
    # Returns an error text, or None if everything is fine.
    @staticmethod
    def check_transaction(tx, balances, nonces):
        required = {"sender", "receiver", "amount", "nonce",
                    "public_key", "signature"}
        if not isinstance(tx, dict) or set(tx) != required:
            return "필드 오류"  # field error
        if tx["sender"] not in balances or tx["receiver"] not in balances:
            return "미등록 주소"  # unknown address
        if type(tx["amount"]) is not int or tx["amount"] <= 0:
            return "금액 오류"  # amount error
        if type(tx["nonce"]) is not int or tx["nonce"] != nonces[tx["sender"]]:
            return "nonce 오류"  # nonce error
        if not verify_signature(tx):
            return "서명 오류"  # signature error
        if balances[tx["sender"]] < tx["amount"]:
            return "잔액 부족"  # not enough balance
        return None

    # STEP 12. Add a checked transaction to the pending list
    def submit(self, tx):
        balances, nonces = self.pending_state()
        error = self.check_transaction(tx, balances, nonces)
        if error:
            return False, error
        self.pending.append(dict(tx))
        return True, "거래 대기 목록에 등록"  # added to pending list

    # STEP 13 and 14. Mine a block (proof of work)
    def mine(self):
        if not self.pending:
            return None
        candidate = {
            "index": len(self.chain),
            "timestamp": int(time.time()),
            "transactions": [dict(t) for t in self.pending],
            "previous_hash": self.chain[-1]["hash"],
            "nonce": 0,
            "difficulty": self.difficulty,
        }
        target = "0" * candidate["difficulty"]
        while True:
            digest = sha256_hex(candidate)
            if digest.startswith(target):
                candidate["hash"] = digest
                break
            candidate["nonce"] += 1
        self.chain.append(candidate)
        self.pending.clear()
        return candidate

    # STEP 15. Check the whole chain
    def valid_chain(self):
        # Genesis block: hash must match its own data
        genesis = self.chain[0]
        g_body = {k: v for k, v in genesis.items() if k != "hash"}
        if genesis["index"] != 0 or sha256_hex(g_body) != genesis["hash"]:
            return False

        balances = dict(self.initial)
        nonces = {a: 0 for a in self.initial}
        prev_hash = genesis["hash"]

        for i, block in enumerate(self.chain[1:], start=1):
            # 1. Link to the previous block
            if block["previous_hash"] != prev_hash:
                return False
            if block["index"] != i:
                return False
            # 2. The stored hash must match the block data
            body = {k: v for k, v in block.items() if k != "hash"}
            if sha256_hex(body) != block["hash"]:
                return False
            # 3. Proof of work
            if not block["hash"].startswith("0" * block["difficulty"]):
                return False
            # 4. Check every transaction again
            for tx in block["transactions"]:
                if self.check_transaction(tx, balances, nonces) is not None:
                    return False
                balances[tx["sender"]] -= tx["amount"]
                balances[tx["receiver"]] += tx["amount"]
                nonces[tx["sender"]] += 1
            prev_hash = block["hash"]
        return True


# ---------------------------------------------------------------
# STEP 16. Console test (run: python blockchain_core.py)
# ---------------------------------------------------------------
if __name__ == "__main__":
    minsu, jiwoo, seoyeon = (Wallet(n) for n in ("민수", "지우", "서연"))
    chain = Blockchain({minsu.address: 20,
                        jiwoo.address: 10,
                        seoyeon.address: 0})

    tx = minsu.create_transaction(jiwoo.address, 5, 0)
    print("거래 등록:", chain.submit(tx))
    print("중복 등록:", chain.submit(tx))
    block = chain.mine()
    print("채굴 해시:", block["hash"])
    print("체인 유효:", chain.valid_chain())

    balances, _ = chain.confirmed_state()
    print("최종 잔액:", balances[minsu.address],
          balances[jiwoo.address], balances[seoyeon.address])

    # Practice check 1: change the amount after signing
    tampered = minsu.create_transaction(jiwoo.address, 5, 1)
    tampered["amount"] = 9
    print("변조 거래:", chain.submit(tampered))
