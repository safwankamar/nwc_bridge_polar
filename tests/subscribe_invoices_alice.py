import os
import json
import base64
import codecs
import requests
import logging
import time
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AliceSubscriber")

# Load environment variables from .env
load_dotenv()

def check_connectivity(rest_url, headers, cert_path):
    """Verify we can at least reach the node before subscribing."""
    url = f"{rest_url.rstrip('/')}/v1/getinfo"
    try:
        r = requests.get(url, headers=headers, verify=cert_path, timeout=5)
        r.raise_for_status()
        info = r.json()
        logger.info(f"✅ Connected to Alice: {info.get('alias')} ({info.get('identity_pubkey')})")
        return True
    except Exception as e:
        logger.error(f"❌ Basic connectivity check failed: {e}")
        return False

def subscribe_invoices(rest_url, headers, cert_path):
    """
    Subscribe to invoice updates from LND via REST stream.
    """
    url = f"{rest_url.rstrip('/')}/v1/invoices/subscribe"
    
    try:
        logger.info(f"Connecting to LND invoice stream at {url}...")
        # Use a session for potential connection pooling
        session = requests.Session()
        
        r = session.get(
            url,
            headers=headers,
            stream=True,
            verify=cert_path,
            timeout=None # Keep connection open
        )
        r.raise_for_status()
        logger.info("Connection established. Waiting for invoice updates...")

        for line in r.iter_lines():
            if line:
                try:
                    update = json.loads(line.decode("utf-8"))
                    # LND REST stream wraps results in a "result" field
                    invoice = update.get("result", update)
                    
                    state = invoice.get("state", "UNKNOWN")
                    r_hash = invoice.get("r_hash", "N/A")
                    memo = invoice.get("memo", "")
                    amount = invoice.get("value", "0")
                    
                    if state == "SETTLED":
                        logger.info(f"✅ Invoice SETTLED: Hash={r_hash}, Amt={amount} sat, Memo='{memo}'")
                    else:
                        logger.info(f"📢 Invoice Update [{state}]: Hash={r_hash}, Memo='{memo}'")
                        
                    # Print full JSON for debugging
                    print(json.dumps(invoice, indent=2))
                    print("-" * 50)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode JSON: {e} | Line: {line}")
                except Exception as e:
                    logger.error(f"Error processing update: {e}")
            else:
                # Keep-alives are usually empty lines
                pass

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        if e.response is not None:
            logger.error(f"Response: {e.response.text}")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection Error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

def main():
    # Load Alice's LND configuration
    rest_url = os.getenv("ALICE_LND_REST")
    macaroon_path = os.getenv("ALICE_MACAROON_PATH")
    cert_path = os.getenv("ALICE_TLS_CERT_PATH")

    # Load Bob's LND configuration
    # rest_url = os.getenv("BOB_LND_REST")
    # macaroon_path = os.getenv("BOB_MACAROON_PATH")
    # cert_path = os.getenv("BOB_TLS_CERT_PATH")

    if not all([rest_url, macaroon_path, cert_path]):
        logger.error("Missing Alice's LND configuration in .env file.")
        print("Required: ALICE_LND_REST, ALICE_MACAROON_PATH, ALICE_TLS_CERT_PATH")
        return

    # Prepare Headers (Load Macaroon)
    try:
        if not os.path.exists(macaroon_path):
            logger.error(f"Macaroon file not found at: {macaroon_path}")
            return
            
        with open(macaroon_path, "rb") as f:
            macaroon = codecs.encode(f.read(), "hex").decode()
        headers = {"Grpc-Metadata-macaroon": macaroon}
    except Exception as e:
        logger.info(f"Error loading macaroon: {e}")
        return

    print("\n" + "="*50)
    print("      ALICE LND INVOICE SUBSCRIBER (Standalone)")
    print("="*50)
    print(f"Node URL: {rest_url}")
    print(f"Cert Path: {cert_path}")
    print("Press Ctrl+C to stop.\n")

    if check_connectivity(rest_url, headers, cert_path):
        try:
            subscribe_invoices(rest_url, headers, cert_path)
        except KeyboardInterrupt:
            print("\nStopping subscription...")
    else:
        print("\n❌ Failed to connect to LND. Please check if the node is running.")

if __name__ == "__main__":
    main()
