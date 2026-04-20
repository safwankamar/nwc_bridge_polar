import os
import json
import codecs
import requests
from dotenv import load_dotenv

load_dotenv()

def settle_invoice_v2(rest_url, headers, cert, payment_request: str):
    """
    Pay a BOLT11 invoice using LND's SendPaymentV2 streaming API.
    POST /v2/router/send
    """
    try:
        data = {
            "payment_request": payment_request,
            "fee_limit_sat": "10",
            "timeout_seconds": 60
        }

        r = requests.post(
            f"{rest_url}/v2/router/send",
            headers=headers,
            json=data,
            verify=cert,
            stream=True                         # Required: endpoint streams status updates
        )
        r.raise_for_status()

        print("\n📡 Streaming payment updates...\n")

        for raw_line in r.iter_lines():
            if not raw_line:
                continue

            update = json.loads(raw_line)
            result = update.get("result", update)   # REST wraps response in {"result": {...}}
            status = result.get("status", "UNKNOWN")

            print(f"  ↳ Status: {status}")

            if status == "SUCCEEDED":
                return {"success": True, "result": result}

            elif status == "FAILED":
                reason = result.get("failure_reason", "UNKNOWN_REASON")
                return {"success": False, "error": f"Payment failed: {reason}", "result": result}

        return {"success": False, "error": "Stream ended without a final status."}

    except requests.exceptions.HTTPError as e:
        try:
            error_body = e.response.json()
        except Exception:
            error_body = e.response.text
        return {"success": False, "error": error_body}

    except Exception as e:
        return {"success": False, "error": str(e)}


def load_node_config(prefix: str):
    """Load LND node config from .env using a given prefix (ALICE or BOB)."""
    rest_url   = os.getenv(f"{prefix}_LND_REST")
    mac_path   = os.getenv(f"{prefix}_MACAROON_PATH")
    cert_path  = os.getenv(f"{prefix}_TLS_CERT_PATH")

    if not all([rest_url, mac_path, cert_path]):
        raise ValueError(f"Missing .env config for {prefix}. "
                         f"Need {prefix}_LND_REST, {prefix}_MACAROON_PATH, {prefix}_TLS_CERT_PATH")

    with open(mac_path, "rb") as f:
        macaroon = codecs.encode(f.read(), "hex").decode()

    headers = {"Grpc-Metadata-macaroon": macaroon}
    return rest_url, headers, cert_path


def main():
    print("=" * 50)
    print("   ⚡ LND SendPaymentV2 — Invoice Payer Tester")
    print("=" * 50)

    # --- Choose which node is PAYING ---
    print("\nWhich node is PAYING the invoice?")
    print("  1 → Alice")
    print("  2 → Bob")
    choice = input("\nEnter choice (1 or 2): ").strip()

    prefix_map = {"1": "ALICE", "2": "BOB"}
    prefix = prefix_map.get(choice)

    if not prefix:
        print("❌ Invalid choice. Exiting.")
        return

    # --- Load config ---
    try:
        rest_url, headers, cert_path = load_node_config(prefix)
    except ValueError as e:
        print(f"❌ Config Error: {e}")
        return
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        return

    print(f"\n✅ Loaded config for: {prefix}")
    print(f"   Node REST URL : {rest_url}")
    print(f"   TLS Cert      : {cert_path}")

    # --- Input invoice ---
    print("\n" + "-" * 50)
    invoice = input("Paste the BOLT11 invoice (lnbc...): ").strip()

    if not invoice:
        print("❌ Invoice cannot be empty.")
        return

    if not invoice.lower().startswith("lnbc") and not invoice.lower().startswith("lntb"):
        print("⚠️  Warning: Invoice doesn't look like a standard BOLT11 string.")
        confirm = input("Continue anyway? (y/n): ").strip().lower()
        if confirm != "y":
            return

    # --- Pay ---
    print("\n⏳ Sending payment via /v2/router/send ...")
    print("-" * 50)

    response = settle_invoice_v2(rest_url, headers, cert_path, invoice)

    print("-" * 50)

    if response.get("success"):
        result = response["result"]
        print("\n✅  Payment SUCCEEDED!")
        print(f"   Payment Hash     : {result.get('payment_hash', 'N/A')}")
        print(f"   Preimage         : {result.get('payment_preimage', 'N/A')}")
        print(f"   Amount (sats)    : {result.get('value_sat', 'N/A')}")
        print(f"   Fee paid (sats)  : {result.get('fee_sat', 'N/A')}")
        print(f"   Created (ns)     : {result.get('creation_time_ns', 'N/A')}")
        print("\n📄 Full Response:")
        print(json.dumps(result, indent=2))

    else:
        print("\n❌  Payment FAILED!")
        print(f"   Reason : {response.get('error', 'Unknown error')}")
        if "result" in response:
            print("\n📄 Full Response:")
            print(json.dumps(response["result"], indent=2))


if __name__ == "__main__":
    main()