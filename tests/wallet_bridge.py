import asyncio
import json
import time
import os
import certifi
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secp256k1
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Fix SSL certificate issues on macOS
os.environ["SSL_CERT_FILE"] = certifi.where()

from nostr_tools import Relay, Client, Event, Filter, generate_event
from lnd_node import LNDNode

# ------------------------------
# CONFIGURATION
# ------------------------------
RELAY_URL = os.getenv("relay_url", "wss://relay.getalby.com/v1")


def get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    """
    Compute NIP-04 shared secret (raw x-coordinate of d*P).
    Used for Nostr Wallet Connect (NIP-47) encryption.
    """
    # Clean inputs
    privkey_hex = privkey_hex.strip() if privkey_hex else ""
    pubkey_hex = pubkey_hex.strip() if pubkey_hex else ""

    try:
        # Use secp256k1 directly for ECDH
        priv = secp256k1.PrivateKey(bytes.fromhex(privkey_hex))
        # Nostr pubkeys are 32-byte x-only. Prepend 02 for compressed even point.
        pub = secp256k1.PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
        # Standard NIP-04: raw x-coordinate of the shared point
        shared_point = pub.tweak_mul(priv.private_key)
        return shared_point.serialize(compressed=False)[1:33]
    except Exception as e:
        logger.error(
            f"Error computing shared secret. "
            f"pubkey_hex='{pubkey_hex}' (len={len(pubkey_hex)}), "
            f"privkey_hex_len={len(privkey_hex)}. Error: {e}"
        )
        raise


def nip04_encrypt(privkey_hex: str, pubkey_hex: str, message: str) -> str:
    """Encrypt message using NIP-04 (AES-256-CBC)."""
    shared_secret = get_shared_secret(privkey_hex, pubkey_hex)
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # PKCS7 Padding
    pad_len = 16 - (len(message) % 16)
    padded_message = message.encode() + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return (
        base64.b64encode(ciphertext).decode() + "?iv=" + base64.b64encode(iv).decode()
    )


def nip04_decrypt(
    privkey_hex: str, pubkey_hex: str, encrypted_content: str
) -> str | None:
    """Decrypt message using NIP-04 (AES-256-CBC)."""
    shared_secret = get_shared_secret(privkey_hex, pubkey_hex)
    try:
        if "?iv=" not in encrypted_content:
            return None

        parts = encrypted_content.split("?iv=")
        ciphertext = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])

        cipher = Cipher(
            algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()

        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_message[-1]

        if not (1 <= pad_len <= 16):
            return padded_message.decode("utf-8", errors="ignore")

        return padded_message[:-pad_len].decode("utf-8")
    except Exception:
        return None


# ------------------------------
# NWC Bridge Class
# ------------------------------
class NWCBridge:
    def __init__(self, relay_url, private_key_hex, public_key_hex, lnd_node: LNDNode, name="Unknown"):
        self.relay_url = relay_url
        self.private_key = private_key_hex
        self.public_key = public_key_hex
        self.node = lnd_node
        self.name = name
        self.relay = Relay(relay_url)
        self.client = Client(self.relay, timeout=None)
        self.rate_limits = {}  # Track {pubkey: [timestamps]}

    async def publish_wallet_info(self):
        """
        Publish wallet info event (methods your wallet supports)
        NIP-47 uses kind 13194 for wallet info.
        """
        methods = ["get_info", "get_balance", "make_invoice", "pay_invoice", "lookup_invoice"]
        event_content = " ".join(methods)

        event_dict = generate_event(
            self.private_key,
            self.public_key,
            kind=13194,
            tags=[],
            content=event_content,
        )
        event = Event.from_dict(event_dict)
        await self.client.publish(event)
        print(f"[{self.name}] Published wallet info (Kind 13194).")

    async def send_response(self, client_pubkey, request_id, result=None, error=None, method=None):
        """Helper to send NWC response (Kind 23195)"""
        res_type = "error" if error else method
        response_content = json.dumps({"result": result, "error": error, "result_type": res_type})
        
        # Encrypt response content
        encrypted_response = nip04_encrypt(self.private_key, client_pubkey, response_content)

        # Create response event (Kind 23195)
        resp_event_dict = generate_event(
            self.private_key,
            self.public_key,
            kind=23195,  # NWC Response
            tags=[["e", request_id], ["p", client_pubkey]],
            content=encrypted_response,
        )
        resp_event = Event.from_dict(resp_event_dict)
        await self.client.publish(resp_event)
        print(f"[{self.name}] Sent Response for {method}. Status: {'Error' if error else 'Success'}")

    async def handle_request(self, event_dict: dict):
        """Handle incoming NWC requests (Kind 23194)"""
        client_pubkey = event_dict.get("pubkey")
        request_id = event_dict.get("id")

        # 1. Rate Limiting Check
        now = time.time()
        last_requests = self.rate_limits.get(client_pubkey, [])
        last_requests = [t for t in last_requests if now - t < 60]  # Rolling 60s window
        if len(last_requests) >= 15:  # Limit: 15 requests per minute
            await self.send_response(client_pubkey, request_id, error={"code": "RATE_LIMITED", "message": "Too many requests"}, method="error")
            return
        last_requests.append(now)
        self.rate_limits[client_pubkey] = last_requests

        try:
            encrypted_content = event_dict.get("content", "")

            # 2. Decrypt request content
            content = nip04_decrypt(self.private_key, client_pubkey, encrypted_content)
            if not content:
                print(f"[{self.name}] Failed to decrypt content from {client_pubkey}")
                return

            data = json.loads(content)
            method = data.get("method")
            params = data.get("params", {})
            print(f"[{self.name}] Received Request: {method}")

            result = None
            error = None

            if method == "get_info":
                result = self.node.get_info()
                if "error" in result:
                    error = {"code": "INTERNAL", "message": result["error"]}
                    result = None

            elif method == "get_balance":
                # balance_data = self.node.get_balance()
                balance_data = self.node.get_channel_balance()
                if "error" in balance_data:
                    error = {"code": "INTERNAL", "message": balance_data["error"]}
                else:
                    result = {"balance": int(balance_data.get("balance", 0)) * 1000}

            elif method == "make_invoice":
                amount_msat = params.get("amount")
                amount_sat = amount_msat // 1000 if amount_msat else 0
                memo = params.get("description", "NWC Invoice")
                inv = self.node.create_invoice(amount_sat, memo)
                if inv and ("payment_request" in inv):
                    result = {
                        "type": "incoming",
                        "invoice": inv.get("payment_request"),
                        "description": memo,
                        "amount": amount_msat,
                        "payment_hash": inv.get("payment_hash"),
                        "created_at": int(time.time()),
                        "expires_at": int(time.time()) + 3600,
                    }
                else:
                    err_msg = inv.get("message") or inv.get("error", "Failed to create invoice")
                    error = {"code": "OTHER", "message": err_msg}

            elif method == "pay_invoice":
                invoice_str = params.get("invoice")
                res = self.node.settle_invoice(invoice_str)
                if res and (res.get("payment_error") or "error" in res):
                    err_msg = res.get("payment_error") or res.get("error") or "Payment failed"
                    if "insufficient" in err_msg.lower() or "not enough" in err_msg.lower():
                        error = {"code": "INSUFFICIENT_BALANCE", "message": err_msg}
                    elif "no_route" in err_msg.lower():
                        error = {"code": "INSUFFICIENT_BALANCE", "message": "No route to destination"}
                    else:
                        error = {"code": "OTHER", "message": err_msg}
                elif not res:
                    error = {"code": "OTHER", "message": "Failed to settle invoice"}
                else:
                    result = {"preimage": res.get("payment_preimage", "unknown")}

            elif method == "list_channels":
                result = self.node.list_channels()
            else:
                error = {"code": "NOT_IMPLEMENTED", "message": f"Method {method} not supported"}

            await self.send_response(client_pubkey, request_id, result=result, error=error, method=method)

        except Exception as e:
            logger.exception(f"[{self.name}] Error handling request")
            await self.send_response(client_pubkey, request_id, error={"code": "INTERNAL", "message": str(e)}, method="error")

    async def run(self):
        """
        Main loop: connect and listen for requests
        """
        print(f"Connecting to relay: {self.relay_url}...")
        async with self.client:
            print("Connected!")

            # 1. Publish wallet info so clients know we are alive
            await self.publish_wallet_info()

            # 2. Subscribe to requests (Kind 23194) sent to our pubkey
            # NIP-47 requests are Kind 23194
            req_filter = Filter(kinds=[23194], p=[self.public_key])
            sub_id = await self.client.subscribe(req_filter)
            print(f"Subscribed to NWC requests. Subscription ID: {sub_id}")

            # 3. Listen for events
            async for message in self.client.listen():
                # message format: ["EVENT", sub_id, event_dict]
                if message[0] == "EVENT" and message[1] == sub_id:
                    event_data = message[2]
                    print("222222")
                    await self.handle_request(event_data)
                elif message[0] == "NOTICE":
                    print(f"Relay Notice: {message[1]}")


# ------------------------------
# RUN
# ------------------------------
async def main():
    users = [
        {
            "name": "Alice",
            "nostr_sk": os.getenv("ALICE_WALLET_SERVICE_SK"),
            "nostr_pk": os.getenv("ALICE_WALLET_SERVICE_PK"),
            "lnd": LNDNode(
                os.getenv("ALICE_LND_REST"),
                os.getenv("ALICE_MACAROON_PATH"),
                os.getenv("ALICE_TLS_CERT_PATH")
            )
        },
        {
            "name": "Bob",
            "nostr_sk": os.getenv("BOB_WALLET_SERVICE_SK"),
            "nostr_pk": os.getenv("BOB_WALLET_SERVICE_PK"),
            "lnd": LNDNode(
                os.getenv("BOB_LND_REST"),
                os.getenv("BOB_MACAROON_PATH"),
                os.getenv("BOB_TLS_CERT_PATH")
            )
        }
    ]

    bridges = []
    for u in users:
        if all([u["nostr_sk"], u["nostr_pk"], u["lnd"].rest_url]):
            bridge = NWCBridge(RELAY_URL, u["nostr_sk"], u["nostr_pk"], u["lnd"], name=u["name"])
            bridges.append(bridge.run())
        else:
            print(f"Skipping {u['name']} due to missing configuration.")

    if not bridges:
        print("No bridges configured correctly. Check your .env file.")
        return

    print(f"Starting {len(bridges)} NWC Bridges...")
    await asyncio.gather(*bridges)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBridges stopped by user.")
