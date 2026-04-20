import os
import asyncio
import json
import logging
import codecs
import httpx
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("InvoiceMonitor")

# Load environment variables
load_dotenv()

async def subscribe_single_invoice_single(rest_url, headers, cert_path, r_hash_hex: str):
    """
    Subscribe to updates for a single invoice.
    GET /v2/invoices/subscribe/{r_hash}
    """
    import base64
    r_hash_bytes = bytes.fromhex(r_hash_hex)
    r_hash_b64 = base64.urlsafe_b64encode(r_hash_bytes).decode('utf-8')
    
    timeout = httpx.Timeout(connect=5.0, read=None, write=10.0, pool=10.0)
    url = f"{rest_url.rstrip('/')}/v2/invoices/subscribe/{r_hash_b64}"

    
    try:
        async with httpx.AsyncClient(
            verify=cert_path,
            timeout=timeout,
            headers=headers,
        ) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()

                async for raw_line in response.aiter_lines():
                    if not raw_line:
                        continue

                    update = json.loads(raw_line)
                    # LND REST stream wraps results in a "result" field
                    invoice = update.get("result", update)
                    yield invoice
    except Exception as e:
        logger.error(f"Error subscribing to invoice {r_hash_hex}: {e}")
        return

async def monitor_invoice(rest_url, headers, cert_path, payment_hash: str):
    """
    Monitor a specific invoice using the v2/invoices/subscribe/{r_hash} endpoint.
    """
    logger.info(f"Starting monitoring for invoice: {payment_hash}")
    
    try:
        async for invoice in subscribe_single_invoice_single(rest_url, headers, cert_path, payment_hash):
            state = invoice.get("state", "UNKNOWN")
            logger.info(f"Update received | State: {state}")
            
            # Print full JSON for clarity
            print(json.dumps(invoice, indent=2))
            print("-" * 60)
            
            if state == "ACCEPTED":
                print("\n💰 HOLD INVOICE IS PAID! Please settle or cancel.\n")
            
            elif state == "SETTLED":
                print("\n✅ INVOICE SETTLED!\n")
                break
            
            elif state in ("CANCELED", "EXPIRED"):
                print(f"\n❌ INVOICE {state}.\n")
                break
                
    except Exception as e:
        logger.error(f"Error during monitoring: {e}")

async def main():
    # Use Alice or Bob credentials from .env
    rest_url = os.getenv("ALICE_LND_REST") or os.getenv("BOB_LND_REST")
    macaroon_path = os.getenv("ALICE_MACAROON_PATH") or os.getenv("BOB_MACAROON_PATH")
    cert_path = os.getenv("ALICE_TLS_CERT_PATH") or os.getenv("BOB_TLS_CERT_PATH")

    if not all([rest_url, macaroon_path, cert_path]):
        logger.error("Missing .env values for LND credentials")
        return

    # Load macaroon and prepare headers
    try:
        with open(macaroon_path, "rb") as f:
            macaroon = codecs.encode(f.read(), "hex").decode()
        headers = {"Grpc-Metadata-macaroon": macaroon}
    except Exception as e:
        logger.error(f"Failed to load macaroon: {e}")
        return

    print("\n" + "=" * 60)
    print("   🔌 STANDALONE LND INVOICE MONITOR (V2)")
    print("=" * 60)
    print(f"Node: {rest_url}")
    
    payment_hash = input("Enter the payment hash to monitor (hex): ").strip()
    
    if not payment_hash:
        print("Payment hash is required.")
        return

    try:
        await monitor_invoice(rest_url, headers, cert_path, payment_hash)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
