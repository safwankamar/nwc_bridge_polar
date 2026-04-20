import asyncio
import json
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

# Fix SSL certificate issues on macOS
os.environ['SSL_CERT_FILE'] = certifi.where()

# Load environment variables
load_dotenv()

from nostr_tools import Relay, Client, Filter, Event, generate_event


def get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    """Compute NIP-04 shared secret."""
    try:
        priv = secp256k1.PrivateKey(bytes.fromhex(privkey_hex))
        pub = secp256k1.PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
        shared_point = pub.tweak_mul(priv.private_key)
        return shared_point.serialize(compressed=False)[1:33]
    except Exception as e:
        logger.error(f"Error computing shared secret: {e}")
        raise


def nip04_encrypt(privkey_hex: str, pubkey_hex: str, message: str) -> str:
    """Encrypt message using NIP-04."""
    shared_secret = get_shared_secret(privkey_hex, pubkey_hex)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(message) % 16)
    padded_message = message.encode() + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode() + "?iv=" + base64.b64encode(iv).decode()


def nip04_decrypt(privkey_hex: str, pubkey_hex: str, encrypted_content: str) -> str | None:
    """Decrypt message using NIP-04."""
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

# Configuration from .env
RELAY_URL = os.getenv("relay_url", "wss://relay.getalby.com/v1")
CLIENT_PUB = os.getenv("Client_Pub")
CLIENT_SK = os.getenv("Client_Secret")
WALLET_SERVICE_PUB = os.getenv("Wallet_Service_Pub")

async def test_nwc_flow():
    """
    Full NWC Flow: Send Request (23194) -> Receive Response (23195)
    """
    if not all([CLIENT_PUB, CLIENT_SK, WALLET_SERVICE_PUB]):
        print("Error: Client_Pub, Client_Secret, or Wallet_Service_Pub missing in .env")
        return

    print(f"Connecting to relay: {RELAY_URL}...")
    relay = Relay(RELAY_URL)
    client = Client(relay,timeout=600)
    
    async with client:
        print("Connected!")
        
        # 1. SUBSCRIBE to Kind 23195 responses first
        # We listen for events where we are the recipient ('p' tag)
        resp_filter = Filter(
            kinds=[23195], 
            p=[CLIENT_PUB]
        )
        sub_id = await client.subscribe(resp_filter)
        print(f"Subscribed to NWC responses (Kind 23195). Waiting for bridge...")

        # 2. CREATE AND SEND Request (Kind 23194)
        # We'll request the balance as a test
        request_data = {
            "method": "get_balance",
            "params": {}
        }
        
        print(f"Creating request: {request_data['method']}...")
        
        # Encrypt the request content
        encrypted_request = nip04_encrypt(CLIENT_SK, WALLET_SERVICE_PUB, json.dumps(request_data))
        
        event_dict = generate_event(
            CLIENT_SK,
            CLIENT_PUB,
            kind=23194,
            tags=[["p", WALLET_SERVICE_PUB]], # Tag the bridge's pubkey
            content=encrypted_request
        )
        request_event = Event.from_dict(event_dict)
        
        # Publish the request
        await client.publish(request_event)
        print(f"Request published! Event ID: {request_event.id}")
        print("Waiting for response...")

        # 3. LISTEN for response
        async for message in client.listen():
            # message format: ["EVENT", sub_id, event_dict]
            if message[0] == "EVENT" and message[1] == sub_id:
                event_data = message[2]
                
                # Check if this response is linked to our request ID via 'e' tag
                e_tags = [t[1] for t in event_data.get('tags', []) if t[0] == 'e']
                
                if request_event.id in e_tags:
                    print(f"\n[RECEIVED RESPONSE]")
                    print(f"From Bridge: {event_data['pubkey']}")
                    
                    try:
                        # Decrypt response content
                        decrypted_content = nip04_decrypt(CLIENT_SK, event_data['pubkey'], event_data['content'])
                        if decrypted_content:
                            content = json.loads(decrypted_content)
                            print("Parsed Decrypted Content:", json.dumps(content, indent=2))
                        else:
                            print("Failed to decrypt response content.")
                    except Exception as e:
                        print(f"Error decrypting response: {e}")
                        print("Raw Content:", event_data['content'])
                    
                    # Continuing to listen for more events...
            elif message[0] == "NOTICE":
                print(f"Relay Notice: {message[1]}")

if __name__ == "__main__":
    try:
        asyncio.run(test_nwc_flow())
    except KeyboardInterrupt:
        print("\nStopped.")

