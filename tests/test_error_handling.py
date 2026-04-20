import asyncio
import json
import os
import certifi
import base64
import logging
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secp256k1
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fix SSL certificate issues on macOS
os.environ['SSL_CERT_FILE'] = certifi.where()

# Load environment variables
load_dotenv()

from nostr_tools import Relay, Client, Filter, Event, generate_event

def get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    try:
        priv = secp256k1.PrivateKey(bytes.fromhex(privkey_hex))
        pub = secp256k1.PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
        shared_point = pub.tweak_mul(priv.private_key)
        return shared_point.serialize(compressed=False)[1:33]
    except Exception as e:
        logger.error(f"Error computing shared secret: {e}")
        raise

def nip04_encrypt(privkey_hex: str, pubkey_hex: str, message: str) -> str:
    shared_secret = get_shared_secret(privkey_hex, pubkey_hex)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(message) % 16)
    padded_message = message.encode() + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode() + "?iv=" + base64.b64encode(iv).decode()

def nip04_decrypt(privkey_hex: str, pubkey_hex: str, encrypted_content: str) -> str | None:
    shared_secret = get_shared_secret(privkey_hex, pubkey_hex)
    try:
        if "?iv=" not in encrypted_content: return None
        parts = encrypted_content.split("?iv=")
        ciphertext = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_message[-1]
        if not (1 <= pad_len <= 16): return padded_message.decode("utf-8", errors="ignore")
        return padded_message[:-pad_len].decode("utf-8")
    except Exception: return None

# Configuration
RELAY_URL = os.getenv("relay_url", "wss://relay.getalby.com/v1")
CLIENT_PUB = os.getenv("Client_Pub")
CLIENT_SK = os.getenv("Client_Secret")
# Use Alice's Pubkey for testing
BRIDGE_PUB = os.getenv("ALICE_WALLET_SERVICE_PK")

async def send_request(client, method, params={}):
    request_data = {"method": method, "params": params}
    encrypted_request = nip04_encrypt(CLIENT_SK, BRIDGE_PUB, json.dumps(request_data))
    event_dict = generate_event(
        CLIENT_SK, CLIENT_PUB,
        kind=23194,
        tags=[["p", BRIDGE_PUB]],
        content=encrypted_request
    )
    request_event = Event.from_dict(event_dict)
    await client.publish(request_event)
    return request_event.id

async def test_errors():
    if not all([CLIENT_PUB, CLIENT_SK, BRIDGE_PUB]):
        print("Missing config in .env")
        return

    relay = Relay(RELAY_URL)
    client = Client(relay, timeout=600)
    
    async with client:
        print("Connected!")
        resp_filter = Filter(kinds=[23195], p=[CLIENT_PUB])
        sub_id = await client.subscribe(resp_filter)

        print("\n--- Testing NOT_IMPLEMENTED ---")
        req_id = await send_request(client, "unknown_method")
        
        # Listen for response
        async for message in client.listen():
            if message[0] == "EVENT" and message[1] == sub_id:
                event_data = message[2]
                e_tags = [t[1] for t in event_data.get('tags', []) if t[0] == 'e']
                if req_id in e_tags:
                    decrypted = nip04_decrypt(CLIENT_SK, event_data['pubkey'], event_data['content'])
                    print("Response:", decrypted)
                    break
        
        print("\n--- Testing RATE_LIMITED ---")
        print("Sending 20 requests rapidly...")
        req_ids = []
        for i in range(20):
            rid = await send_request(client, "get_info")
            req_ids.append(rid)
        
        rate_limited_hit = False
        async for message in client.listen():
            if message[0] == "EVENT" and message[1] == sub_id:
                event_data = message[2]
                decrypted = nip04_decrypt(CLIENT_SK, event_data['pubkey'], event_data['content'])
                if decrypted:
                    res = json.loads(decrypted)
                    if res.get("error") and res["error"]["code"] == "RATE_LIMITED":
                        print("SUCCESS: Received RATE_LIMITED error!")
                        rate_limited_hit = True
                        break
        if not rate_limited_hit:
            print("FAILED: Did not receive RATE_LIMITED error.")

if __name__ == "__main__":
    asyncio.run(test_errors())
