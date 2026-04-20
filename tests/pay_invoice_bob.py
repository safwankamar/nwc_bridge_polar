import os
import json
import base64
import codecs
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

def settle_invoice_local(rest_url, headers, cert, invoice):
    """Local function to call LND settle invoice endpoint."""
    try:
        data = {"payment_request": invoice}
        # LND REST endpoint for sending payments: POST /v1/channels/transactions
        r = requests.post(
            f"{rest_url}/v1/channels/transactions",
            headers=headers,
            json=data,
            verify=cert
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}



def main():
    # Load Bob's LND configuration
    rest_url = os.getenv("BOB_LND_REST")
    macaroon_path = os.getenv("BOB_MACAROON_PATH")
    cert_path = os.getenv("BOB_TLS_CERT_PATH")

    if not all([rest_url, macaroon_path, cert_path]):
        print("Error: Missing Bob's LND configuration in .env file.")
        return

    # Prepare Headers (Load Macaroon)
    try:
        with open(macaroon_path, "rb") as f:
            macaroon = codecs.encode(f.read(), "hex").decode()
        headers = {"Grpc-Metadata-macaroon": macaroon}
    except Exception as e:
        print(f"Error loading macaroon: {e}")
        return

    print("\n--- Bob's Standalone Invoice Payer ---")
    print(f"Node: {rest_url}")
    
    # Prompt for invoice
    invoice = input("\nPlease enter the BOLT11 invoice (payment_request): ").strip()

    if not invoice:
        print("Error: Invoice cannot be empty.")
        return

    print("\nAttempting to pay...")
    
    # Call the local function instead of a class method
    result = settle_invoice_local(rest_url, headers, cert_path, invoice)

    if "error" in result:
        print(f"\n❌ Request Failed!")
        print(f"Error: {result['error']}")
    else:
        # Check for LND-level errors
        payment_error = result.get("payment_error")
        if payment_error:
            # Note: "payment is in transition" is technically a successful initiation
            if payment_error == "payment is in transition":
                print("\n🟡 Payment Initiated (In Transition)")
            else:
                print(f"\n❌ Payment Error: {payment_error}")
        else:
            print("\n✅ Payment Successful!")
        
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
