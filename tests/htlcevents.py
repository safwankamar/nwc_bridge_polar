import os
import json
import logging
import codecs
import requests
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("HTLCSubscriber")

# Load environment variables
load_dotenv()


def subscribe_htlcs(rest_url, headers, cert_path):
    """
    Subscribe to HTLC events (captures keysend payments).
    """
    url = f"{rest_url}/v2/router/htlcevents"

    while True:  # auto-reconnect loop
        try:
            logger.info(f"Connecting to HTLC stream: {url}")

            with requests.get(
                url,
                headers=headers,
                stream=True,
                verify=cert_path
            ) as r:

                r.raise_for_status()
                logger.info("✅ Connected. Listening for HTLC events...\n")

                for line in r.iter_lines():
                    if not line:
                        continue

                    try:
                        update = json.loads(line.decode("utf-8"))
                        # print(update)

                        # LND wraps sometimes in "result"
                        event = update.get("result", update)

                        # DEBUG: uncomment to see everything
                        # print(json.dumps(event, indent=2))

                        event_type = event.get("event_type")

                        # We only care about settled incoming HTLCs
                        if event_type == "RECEIVE":
                            htlc = event["settle_event"]

                            preimage = htlc.get("preimage")

                            custom_records = htlc.get("custom_records", {})

                            logger.info(f"💰 Keysend received: {preimage}")

                            output = {
                                "type": "keysend",
                                "preimage": preimage,
                                "timestamp": event.get("timestamp_ns"),
                                "custom_records": custom_records,
                                "raw": event
                            }

                            print(json.dumps(output, indent=2))
                            print("-" * 60)

                        else:
                            # Optional: log other events for debugging
                            pass

                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error: {e}")
                    except Exception as e:
                        logger.error(f"Processing error: {e}")

        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            logger.info("🔁 Reconnecting in 3 seconds...\n")
            import time
            time.sleep(3)


def main():
    rest_url = os.getenv("BOB_LND_REST")
    macaroon_path = os.getenv("BOB_MACAROON_PATH")
    cert_path = os.getenv("BOB_TLS_CERT_PATH")

    if not all([rest_url, macaroon_path, cert_path]):
        logger.error("Missing .env values")
        print("Required: BOB_LND_REST, BOB_MACAROON_PATH, BOB_TLS_CERT_PATH")
        return

    # Load macaroon
    try:
        with open(macaroon_path, "rb") as f:
            macaroon = codecs.encode(f.read(), "hex").decode()

        headers = {
            "Grpc-Metadata-macaroon": macaroon
        }

    except Exception as e:
        logger.error(f"Macaroon load error: {e}")
        return

    print("\n" + "=" * 60)
    print("   🔌 BOB HTLC (KEYSEND) LISTENER")
    print("=" * 60)
    print(f"Node: {rest_url}")
    print("Waiting for payments...\n")

    try:
        subscribe_htlcs(rest_url, headers, cert_path)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()