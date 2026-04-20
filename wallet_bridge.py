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
import hashlib
from coincurve import PublicKeyXOnly, PrivateKey, PublicKey
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

# Supported methods advertised in the info event
SUPPORTED_METHODS = [
    "pay_invoice",
    "pay_keysend",
    "get_balance",
    "get_info",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "list_payments",
]

# Supported notification types
SUPPORTED_NOTIFICATIONS = ["payment_received", "payment_sent", "hold_invoice_accepted"]


def get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    """
    Compute NIP-04 shared secret (raw x-coordinate of d*P).
    Used for Nostr Wallet Connect (NIP-47) encryption.
    """
    privkey_hex = privkey_hex.strip() if privkey_hex else ""
    pubkey_hex = pubkey_hex.strip() if pubkey_hex else ""

    try:
        priv = secp256k1.PrivateKey(bytes.fromhex(privkey_hex))
        pub = secp256k1.PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
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


def nip04_decrypt(privkey_hex: str, pubkey_hex: str, encrypted_content: str) -> str | None:
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
# Response Helpers
# ------------------------------

def make_success_response(method: str, result: dict) -> dict:
    """
    Build a spec-compliant NIP-47 success response.
    - result_type MUST be the method name
    - error MUST be null on success
    """
    return {
        "result_type": method,
        "error": None,
        "result": result,
    }


def make_error_response(method: str, code: str, message: str) -> dict:
    """
    Build a spec-compliant NIP-47 error response.
    - result_type MUST still be the method name (never "error")
    - result MUST be null on error
    """
    return {
        "result": None,
        "error": {
            "code": code,
            "message": message,
        },
        "result_type": "error",
    }


def map_transaction(tx: dict, tx_type: str = "incoming") -> dict:
    """
    Map an LND invoice/payment dict to the NIP-47 transaction object shape.
    Used by make_invoice, lookup_invoice, list_transactions.
    """
    # Determine settled state
    settled = tx.get("settled", False)
    state = "settled" if settled else "pending"

    # LND stores amounts in satoshis; NIP-47 uses millisatoshis
    # Fallback through various LND and internal field names
    amount_sat = int(tx.get("value") or tx.get("amt") or tx.get("amount") or tx.get("value_sat") or tx.get("num_satoshis") or 0)
    fees_sat = int(tx.get("fee_sat") or tx.get("fee") or 0)

    created_at = int(tx.get("creation_date") or tx.get("creation_time_ns", 0) or 0)
    # creation_time_ns is nanoseconds; convert if needed
    if created_at > 1e12:
        created_at = created_at // 1_000_000_000

    settle_date = int(tx.get("settle_date", 0) or 0)
    expiry_seconds = int(tx.get("expiry", 3600) or 3600)
    expires_at = created_at + expiry_seconds if created_at else None

    result = {
        "type": tx_type,
        "state": state,
        "invoice": tx.get("payment_request") or tx.get("invoice"),
        "description": tx.get("memo") or tx.get("description"),
        "description_hash": tx.get("description_hash"),
        "preimage": tx.get("r_preimage") or tx.get("payment_preimage"),
        "payment_hash": tx.get("r_hash") or tx.get("payment_hash"),
        "amount": amount_sat * 1000,       # sats → msats
        "fees_paid": fees_sat * 1000,      # sats → msats
        "created_at": created_at,
        "expires_at": expires_at,
        "settled_at": settle_date if settle_date else None,
    }
    # Remove None optional fields to keep responses clean (but keep required ones)
    return {k: v for k, v in result.items() if v is not None or k in (
        "type", "state", "payment_hash", "amount", "fees_paid", "created_at"
    )}


def normalize_hash(h: str) -> str:
    """Ensure payment hash is in hex format. Converts from Base64 if needed."""
    if not h:
        return ""
    # If it's already a 64-char hex string, just return it
    if len(h) == 64:
        try:
            int(h, 16)
            return h.lower()
        except ValueError:
            pass
    
    # Try decoding from base64 (LND's r_hash format)
    try:
        if len(h) >= 43: # Base64 for 32 bytes is 44 chars (or 43 with stripped padding)
            decoded = base64.b64decode(h)
            if len(decoded) == 32:
                return decoded.hex().lower()
    except Exception:
        pass
        
    return h.lower()

# ------------------------------
# NWC Bridge Class
# ------------------------------
class NWCBridge:
    def __init__(self, relay_url, private_key_hex, public_key_hex, client_pk, lnd_node: LNDNode, name="Unknown"):
        self.relay_url = relay_url
        self.private_key = private_key_hex
        self.public_key = public_key_hex
        self.client_pk = client_pk
        self.node = lnd_node
        self.name = name
        self.relay = Relay(relay_url)
        self.client = Client(self.relay, timeout=None)
        self.rate_limits = {}  # {pubkey: [timestamps]}
        self.loop = asyncio.get_event_loop()

    async def publish_wallet_info(self):
        """
        Publish wallet info event (Kind 13194).
        Per spec:
        - content: space-separated list of supported methods
        - tags: ["encryption", "nip44_v2 nip04"] and ["notifications", ...]
        """
        event_content = " ".join(SUPPORTED_METHODS) + " notifications"

        tags = [
            # Advertise both NIP-44 (preferred) and NIP-04 (legacy compat)
            ["encryption", "nip44_v2 nip04"],
            # Advertise supported notification types
            ["notifications", " ".join(SUPPORTED_NOTIFICATIONS)],
        ]

        event_dict = generate_event(
            self.private_key,
            self.public_key,
            kind=13194,
            tags=tags,
            content=event_content,
        )
        event = Event.from_dict(event_dict)
        await self.client.publish(event)
        print(f"[{self.name}] Published wallet info (Kind 13194): {event_content}")

    async def send_response(self, client_pubkey: str, request_id: str, response_body: dict):
        """
        Encrypt and publish a NIP-47 response (Kind 23195).

        response_body must already be a spec-compliant dict with keys:
            result_type, error (null or object), result (null or object)
        """
        response_json = json.dumps(response_body)
        encrypted_response = nip04_encrypt(self.private_key, client_pubkey, response_json)

        resp_event_dict = generate_event(
            self.private_key,
            self.public_key,
            kind=23195,
            tags=[
                ["e", request_id],        # id of the request we are responding to
                ["p", client_pubkey],     # public key of the client
            ],
            content=encrypted_response,
        )
        resp_event = Event.from_dict(resp_event_dict)
        
        try:
            # Use send_message instead of publish to avoid concurrent receive() errors
            await self.client.send_message(["EVENT", resp_event.to_dict()])
        except Exception as e:
            logger.error(f"[{self.name}] Failed to publish response: {e}")
            return


        method = response_body.get("result_type", "unknown")
        is_error = response_body.get("error") is not None
        print(f"[{self.name}] Response sent | method={method} | {'ERROR: ' + response_body['error']['code'] if is_error else 'OK'}")

    async def send_notification(self, client_pubkey: str, notification_type: str, notification_data: dict):
        """
        Encrypt and publish a NIP-47 notification (Kind 23196 for NIP-04).
        Per NIP-47:
        - notification_type: type of notification (e.g., payment_received)
        - notification: the data object (same as transaction object)
        """
        content = {
            "notification_type": notification_type,
            "notification": notification_data
        }
        notification_json = json.dumps(content)
        
        # Use NIP-04 for now as it's consistent with responses; use Kind 23196 for NIP-04 compat
        encrypted_content = nip04_encrypt(self.private_key, client_pubkey, notification_json)

        notification_event_dict = generate_event(
            self.private_key,
            self.public_key,
            kind=23196,  # 23196 for NIP-04 compatibility
            tags=[
                ["p", client_pubkey],     # public key of the client
            ],
            content=encrypted_content,
        )
        notification_event = Event.from_dict(notification_event_dict)
        # Use send_message instead of publish to avoid concurrent receive() errors
        await self.client.send_message(["EVENT", notification_event.to_dict()])
        
        print(f"[{self.name}] Notification sent | type={notification_type} | to={client_pubkey[:8]}...")


    async def send_payment_received_notification(self, client_pubkey: str, tx_data: dict):
        """Dedicated helper for payment_received."""
        await self.send_notification(client_pubkey, "payment_received", tx_data)

    async def send_payment_sent_notification(self, client_pubkey: str, tx_data: dict):
        """Dedicated helper for payment_sent."""
        await self.send_notification(client_pubkey, "payment_sent", tx_data)

    async def send_hold_invoice_accepted_notification(self, client_pubkey: str, tx_data: dict):
        """Dedicated helper for hold_invoice_accepted."""
        await self.send_notification(client_pubkey, "hold_invoice_accepted", tx_data)

    async def _listen_for_invoices(self):
        """Background task to listen for invoice settlements from our LND node."""
        print(f"[{self.name}] Started invoice listener.")
        
        def run_subscription():
            try:
                for invoice in self.node.subscribe_invoices():
                    # Process only settled invoices
                    state = invoice.get("state")
                    if state in ("SETTLED", "ACCEPTED") or invoice.get("settled"):
                        payment_hash = normalize_hash(invoice.get("r_hash") or invoice.get("payment_hash", ""))
                        
                        # if payment_hash in PAYMENT_REGISTRY:
                        #     entry = PAYMENT_REGISTRY[payment_hash]
                            # receiver = entry.get("receiver")
                        receiver = self.client_pk
                            
                        if receiver:
                            # Map to NIP-47 transaction object
                            tx_data = map_transaction(invoice, tx_type="incoming")
                                
                            # Dispatch based on state
                            if state == "SETTLED" or invoice.get("settled"):
                                asyncio.run_coroutine_threadsafe(
                                    self.send_payment_received_notification(receiver, tx_data),
                                    self.loop
                                )
                                print(f"[{self.name}] Settlement detected | notifying {receiver[:8]}... (hash={payment_hash[:8]})")
                            elif state == "ACCEPTED":
                                asyncio.run_coroutine_threadsafe(
                                    self.send_hold_invoice_accepted_notification(receiver, tx_data),
                                    self.loop
                                )
                                print(f"[{self.name}] Hold invoice accepted | notifying {receiver[:8]}... (hash={payment_hash[:8]})")
                        # elif state == "SETTLED" and invoice.get("is_keysend")==True:
                        #     asyncio.run_coroutine_threadsafe(
                        #         self.send_payment_received_notification(receiver, tx_data),
                        #         self.loop
                        #     )
                        #     print(f"[{self.name}] Keysend detected | notifying {receiver[:8]}... (hash={payment_hash[:8]})")
                            
            except Exception as e:
                logger.error(f"[{self.name}] Invoice listener thread error: {e}")

        # Run the blocking generator in a separate thread
        await self.loop.run_in_executor(None, run_subscription)

    async def _listen_for_htlc_events(self):
        """Background task to listen for HTLC events (specifically keysends) from our LND node."""
        print(f"[{self.name}] Started HTLC event listener.")

        def run_subscription():
            try:
                for event in self.node.subscribe_htlcs():
                    if event.get("type") == "keysend":
                        raw_event = event.get("raw", {})
                        # HTLC events have a payment_hash
                        payment_hash = normalize_hash(raw_event.get("payment_hash", ""))

                        # Map to NIP-47 transaction object
                        tx_data = {
                            "type": "incoming",
                            "state": "settled",
                            "payment_hash": payment_hash,
                            "preimage": event.get("preimage"),
                            "amount": event.get("amount_sat", 0) * 1000,  # sats -> msats
                            "created_at": int(event.get("timestamp", 0)) // 1_000_000_000 if event.get("timestamp_ns") else int(time.time()),
                            "description": "Keysend payment",
                        }
                        asyncio.run_coroutine_threadsafe(
                            self.send_payment_received_notification(self.client_pk, tx_data),
                            self.loop
                        )

                        # Check if we have a receiver in the registry
                        # if payment_hash in PAYMENT_REGISTRY:
                        #     receiver = PAYMENT_REGISTRY[payment_hash].get("receiver")
                        #     if receiver:
                        #         asyncio.run_coroutine_threadsafe(
                        #             self.send_payment_received_notification(receiver, tx_data),
                        #             self.loop
                        #         )
                        #         print(f"[{self.name}] Keysend detected | notifying {receiver[:8]}... (hash={payment_hash[:8]})")
            except Exception as e:
                logger.error(f"[{self.name}] HTLC event listener thread error: {e}")

        # Run the blocking generator in a separate thread
        await self.loop.run_in_executor(None, run_subscription)

    async def _listen_for_payments(self):
        """Background task to listen for outgoing payment updates from our LND node."""
        print(f"[{self.name}] Started payment listener.")
        try:
            async for payment in self.node.subscribe_payments():
                status = payment.get("status")
                if status == "SUCCEEDED":
                    payment_hash = normalize_hash(payment.get("payment_hash", ""))
                    payer=self.client_pk
                    if payer:
                        # Map to NIP-47 transaction object
                        tx_data = map_transaction(payment, tx_type="outgoing")

                        await self.send_payment_sent_notification(payer, tx_data)
                        print(f"[{self.name}] Payment tracked | notifying {payer[:8]}... (hash={payment_hash[:8]})")
        except Exception as e:
            logger.error(f"[{self.name}] Payment listener error: {e}")

    async def _track_inflight_payment(self, generator, client_pubkey: str):
        """
        Background task to continue consuming the payment stream for an in-flight payment.
        Once the status changes to SUCCEEDED, it sends a notification.
        """
        print(f"[{self.name}] Background tracking started for in-flight payment to {client_pubkey[:8]}...")
        try:
            async for update in generator:
                status = "UNKNOWN"
                result = update
                if "result" in update:
                    result = update["result"]
                
                status = result.get("status", "UNKNOWN")
                
                if status == "SUCCEEDED":
                    # Map to NIP-47 transaction object
                    tx_data = map_transaction(result, tx_type="outgoing")
                    await self.send_payment_sent_notification(client_pubkey, tx_data)
                    print(f"[{self.name}] In-flight payment SUCCEEDED | notifying {client_pubkey[:8]}...")
                    break
                elif status == "FAILED":
                    reason = result.get("failure_reason", "UNKNOWN_REASON")
                    print(f"[{self.name}] In-flight payment FAILED: {reason}")
                    break
                elif status == "IN_FLIGHT":
                    # Still in flight, just continue waiting
                    continue
                else:
                    # Unexpected status or stream end
                    break
        except Exception as e:
            logger.error(f"[{self.name}] Error tracking in-flight payment: {e}")

    async def _track_hold_invoice(self, payment_hash_hex: str):
        """
        Background task to track a specific hold invoice until it is settled or canceled.
        Monitoring starts only for hold invoices.
        """
        print(f"[{self.name}] Starting background tracking for hold invoice: {payment_hash_hex[:8]}...")
        try:
            async for invoice in self.node.subscribe_single_invoice(payment_hash_hex):
                state = invoice.get("state")
                payment_hash = normalize_hash(invoice.get("r_hash") or invoice.get("payment_hash", ""))
                
                # Map to NIP-47 transaction object
                tx_data = map_transaction(invoice, tx_type="incoming")
                
                # When hold invoice is accepted (paid by payer but held)
                if state == "ACCEPTED":
                    # Add custom message as requested
                    tx_data["description"] = (tx_data.get("description") or "") + " (Hold invoice is paid please settle or cancel)"
                    
                    await self.send_hold_invoice_accepted_notification(self.client_pk, tx_data)
                    print(f"[{self.name}] Hold invoice {payment_hash[:8]} is PAID (ACCEPTED). Notifying user to settle or cancel.")
                
                elif state == "SETTLED" or invoice.get("settled"):
                    await self.send_payment_received_notification(self.client_pk, tx_data)
                    print(f"[{self.name}] Hold invoice {payment_hash[:8]} is SETTLED.")
                    break # Stop tracking once settled
                
                elif state in ("CANCELED", "EXPIRED"):
                    print(f"[{self.name}] Hold invoice {payment_hash[:8]} is {state}. Stopping tracking.")
                    break
                    
        except Exception as e:
            logger.error(f"[{self.name}] Error tracking hold invoice {payment_hash_hex}: {e}")


    # ------------------------------------------------------------------
    # Command Handlers
    # ------------------------------------------------------------------

    def _handle_get_info(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        get_info response:
        {
            alias, color, pubkey, network, block_height, block_hash,
            methods, notifications (optional)
        }
        """
        raw = self.node.get_info()
        if "error" in raw:
            return None, {"code": "INTERNAL", "message": raw["error"]}

        result = {
            "alias": raw.get("alias", ""),
            "color": raw.get("color", ""),
            "pubkey": raw.get("identity_pubkey", raw.get("pubkey", "")),
            "network": raw.get("chains", [{}])[0].get("network", "mainnet")
                       if raw.get("chains") else raw.get("network", "mainnet"),
            "block_height": raw.get("block_height", 0),
            "block_hash": raw.get("block_hash", ""),
            "methods": SUPPORTED_METHODS,
            "notifications": SUPPORTED_NOTIFICATIONS,
        }
        return result, None

    def _handle_get_balance(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        get_balance response:
        { "balance": <msats> }
        Balance = local channel balance in msats.
        """
        data = self.node.get_channel_balance()
        if "error" in data:
            return None, {"code": "INTERNAL", "message": data["error"]}

        # LND returns local_balance.sat or balance (sats) depending on API version
        local = data.get("local_balance", {})
        if isinstance(local, dict):
            balance_sat = int(local.get("sat", 0) or 0)
        else:
            balance_sat = int(data.get("balance", 0) or 0)

        return {"balance": balance_sat * 1000}, None  # sats → msats

    def _handle_make_invoice(self, params: dict, client_pubkey: str):
        amount_msat = params.get("amount")
        if not amount_msat:
            return None, {"code": "OTHER", "message": "amount is required"}

        amount_sat = amount_msat // 1000
        description = params.get("description", "")
        expiry = params.get("expiry", 3600)

        inv = self.node.create_invoice(amount_sat, description)
        if not inv or "payment_request" not in inv:
            err_msg = inv.get("message") or inv.get("error", "Failed to create invoice") if inv else "Failed to create invoice"
            return None, {"code": "OTHER", "message": err_msg}

        payment_hash = normalize_hash(inv.get("r_hash") or inv.get("payment_hash", ""))

        # # ✅ STORE RECEIVER
        # PAYMENT_REGISTRY[payment_hash] = {
        #     "receiver": client_pubkey,
        #     "payer": None
        # }
        print(f"[{self.name}] PAYMENT REGISTRY RECEIVER ADDED | hash={payment_hash[:8]}...")
        now = int(time.time())
        result = {
            "type": "incoming",
            "state": "pending",
            "invoice": inv.get("payment_request"),
            "description": description,
            "payment_hash": payment_hash,
            "amount": amount_msat,
            "fees_paid": 0,
            "created_at": now,
            "expires_at": now + expiry,
        }

        return result, None

    async def _handle_pay_invoice(self, params: dict, client_pubkey: str):
        invoice_str = params.get("invoice")
        if not invoice_str:
            return None, {"code": "OTHER", "message": "invoice is required"}

        # ✅ Decode invoice to get payment_hash
        decoded = self.node.lookup_invoice(invoice_str)
        payment_hash = decoded.get("payment_hash")

        it = self.node.settle_invoice_v2(invoice_str).__aiter__()
        try:
            res = await it.__anext__()
        except StopAsyncIteration:
            return None, {"code": "PAYMENT_FAILED", "message": "No response from node"}
       
        if not res:
            return None, {"code": "PAYMENT_FAILED", "message": "Payment failed"}

        # Handle in-flight payments (e.g., hold invoices waiting for receiver to settle)
        if res.get("in_flight"):
            # ✅ Start background tracking to wait for final settlement
            logger.info(f"[{self.name}] Hold invoice {payment_hash[:8]} is payment monitoring.")
            asyncio.create_task(self._track_inflight_payment(it, client_pubkey))
            
            return None, {
                "code": "OTHER",
                "message": "Payment is currently in transition. Once the receiver settles the invoice, we will notify you."
            }

        if "result" in res:
            res = res["result"]

        payment_error = res.get("payment_error") or res.get("error")
        if payment_error:
            return None, {"code": "PAYMENT_FAILED", "message": payment_error}


        fee_msat = int(res.get("fee_msat", 0) or 0)

        result = {
            "preimage": res.get("payment_preimage", ""),
            "fees_paid": fee_msat,
            "payment_hash": payment_hash,
            "amount": int(decoded.get("num_satoshis", 0) or 0) * 1000
        }

        return result, None
    
    def _handle_pay_keysend(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        pay_keysend response:
        { "preimage": "...", "fees_paid": <msats> }
        Params: amount (msats), pubkey, preimage (optional), tlv_records (optional)
        """
        amount_msat = params.get("amount")
        dest_pubkey = params.get("pubkey")

        if not amount_msat or not dest_pubkey:
            return None, {"code": "OTHER", "message": "amount and pubkey are required"}

        amount_sat = amount_msat // 1000
        preimage = params.get("preimage")
        tlv_records = params.get("tlv_records", [])

        res = self.node.keysend(
            dest_pubkey=dest_pubkey,
            amount_sat=amount_sat
        )

        if not res:
            return None, {"code": "PAYMENT_FAILED", "message": "Keysend failed: no response from node"}

        if not res.get("success"):
            err_msg = res.get("error") or res.get("error_body", "Unknown error")
            return None, {"code": "PAYMENT_FAILED", "message": f"Keysend failed: {err_msg}"}

        # The actual payment object is in res["payment"]
        payment = res.get("payment", {})
        payment_hash = normalize_hash(payment.get("payment_hash", ""))


        
        # Check for LND-level failure
        if payment.get("status") == "FAILED":
            reason = payment.get("failure_reason", "Unknown failure")
            return None, {"code": "PAYMENT_FAILED", "message": f"Payment failed: {reason}"}

        # Normalize res to the payment object for field extraction
        res = payment

        fee_sat = int(res.get("fee_sat", 0) or 0)
        fee_msat = int(res.get("fee_msat", fee_sat * 1000) or fee_sat * 1000)
        

        result = {
            "preimage": res.get("payment_preimage", ""),
            "fees_paid": fee_msat,
            "amount": amount_msat,
        }
        return result, None

    def _handle_lookup_invoice(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        lookup_invoice response (full transaction object):
        {
            type, state, invoice, description, description_hash,
            preimage, payment_hash, amount, fees_paid,
            created_at, expires_at, settled_at
        }
        Accepts either payment_hash or invoice (bolt11).
        """
        payment_hash = params.get("payment_hash")
        invoice_str = params.get("invoice")

        if not payment_hash and not invoice_str:
            return None, {"code": "OTHER", "message": "payment_hash or invoice is required"}

        # Use payment_hash if provided, otherwise assume invoice_str is provided
        # (Decoding logic for invoice_str to extract hash may be needed if payment_hash is missing)
        raw = self.node.lookup_invoice(
            invoice=payment_hash or invoice_str,
        )

        if not raw:
            return None, {"code": "NOT_FOUND", "message": "Invoice not found"}

        if "error" in raw:
            code = raw.get("code", "INTERNAL")
            # Map gRPC NOT_FOUND code (5) to spec NOT_FOUND
            if str(code) == "5" or "not found" in str(raw.get("message", "")).lower():
                return None, {"code": "NOT_FOUND", "message": "Invoice not found"}
            return None, {"code": "INTERNAL", "message": raw["error"]}

        result = map_transaction(raw, tx_type="incoming")
        return result, None

    def _handle_list_transactions(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        list_transactions response:
        { "transactions": [ <transaction object>, ... ] }
        Params: from, until, limit, offset, unpaid, type
        """
        from_ts = params.get("from", 0)
        until_ts = params.get("until", int(time.time()))
        limit = params.get("limit", 20)
        offset = params.get("offset", 0)
        include_unpaid = params.get("unpaid", False)
        tx_type = params.get("type")  # "incoming", "outgoing", or None for both

        transactions = []

        # Fetch incoming invoices
        if tx_type in (None, "incoming"):
            invoices_data = self.node.list_invoices(
                num_max_invoices=limit,
                index_offset=offset,
                reversed=True,
            )
            if "error" not in (invoices_data or {}):
                for inv in (invoices_data or {}).get("invoices", []):
                    settled = inv.get("settled", False)
                    creation_date = int(inv.get("creation_date", 0) or 0)

                    # Filter by time range
                    if creation_date < from_ts or creation_date > until_ts:
                        continue
                    # Filter unpaid if not requested
                    if not settled and not include_unpaid:
                        continue

                    transactions.append(map_transaction(inv, tx_type="incoming"))

        # Fetch outgoing payments
        if tx_type in (None, "outgoing"):
            payments_data = self.node.list_payments(
                max_payments=limit,
                index_offset=offset,
                reversed=True,
            )
            if "error" not in (payments_data or {}):
                for pay in (payments_data or {}).get("payments", []):
                    creation_time = int(pay.get("creation_time_ns", pay.get("creation_date", 0)) or 0)
                    if creation_time > 1e12:
                        creation_time = creation_time // 1_000_000_000

                    if creation_time < from_ts or creation_time > until_ts:
                        continue

                    transactions.append(map_transaction(pay, tx_type="outgoing"))

        # Sort descending by created_at
        transactions.sort(key=lambda t: t.get("created_at", 0), reverse=True)

        # Apply limit after merge
        transactions = transactions[:limit]

        return {"transactions": transactions}, None

    def _handle_list_payments(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        list_payments response:
        { "payments": [ <transaction object>, ... ] }
        Params: from, until, limit, offset, reversed
        """
        from_ts = params.get("from", 0)
        until_ts = params.get("until", int(time.time()))
        limit = params.get("limit", 20)
        offset = params.get("offset", 0)
        reversed_order = params.get("reversed", True)

        payments_data = self.node.list_payments(
            max_payments=limit + offset,
            index_offset=offset,
            reversed=reversed_order,
        )

        if "error" in (payments_data or {}):
            return None, {"code": "INTERNAL", "message": payments_data["error"]}

        payments = []
        for pay in (payments_data or {}).get("payments", []):
            creation_time = int(pay.get("creation_time_ns", pay.get("creation_date", 0)) or 0)
            tx_dir = pay.get("type")
            if creation_time > 1e12:
                creation_time = creation_time // 1_000_000_000

            # Filter by time range
            if creation_time < from_ts or creation_time > until_ts:
                continue

            payments.append(map_transaction(pay, tx_type=tx_dir))

        # Apply limit
        payments = payments[:limit]
        # payments.reverse()

        return {"transactions": payments}, None
    
    def _handle_make_hold_invoice(self, params: dict, client_pubkey: str) -> tuple[dict | None, dict | None]:
        """
        make_hold_invoice response:
        {
            "invoice": "<bolt11_invoice>",
            "hash": "<payment_hash>",
            "preimage": "<preimage>",
            "expires_at": <unix_timestamp>,
            "state": "pending"
        }
        """
        amount_msat = params.get("amount")
        if not amount_msat:
            return None, {"code": "OTHER", "message": "amount is required"}

        amount_sat = amount_msat // 1000
        description = params.get("description", "")
        description_hash = params.get("description_hash")
        expiry = params.get("expiry", 3600)
        payment_hash = params.get("payment_hash")

        inv = self.node.create_hold_invoice(amount_sat,payment_hash, description, expiry)
        if not inv or "payment_request" not in inv:
            err_msg = inv.get("message") or inv.get("error", "Failed to create invoice") if inv else "Failed to create invoice"
            return None, {"code": "OTHER", "message": err_msg}

        # Use the payment_hash from request params as LND hodl response doesn't return it
        payment_hash_val = normalize_hash(payment_hash)

        print(f"[{self.name}] PAYMENT REGISTRY RECEIVER ADDED (HOLD) | hash={payment_hash_val[:8]}...")
        
        now = int(time.time())
        result = {
            "type": "incoming",
            "state": "pending",
            "invoice": inv.get("payment_request"),
            "description": description,
            "payment_hash": payment_hash_val,
            "amount": amount_msat,
            "fees_paid": 0,
            "created_at": now,
            "expires_at": now + expiry,
        }
        if description_hash:
            result["description_hash"] = description_hash

        # ✅ Start background tracking for this hold invoice
        asyncio.create_task(self._track_hold_invoice(payment_hash_val))
        print(f"[{self.name}] HOLD INVOICE CREATED | hash={payment_hash_val}")

        return result, None


    def _handle_settle_hold_invoice(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        settle_hold_invoice response: {}
        Params: preimage (hex)
        """
        preimage = params.get("preimage")
        if not preimage:
            return None, {"code": "OTHER", "message": "preimage is required"}

        res = self.node.settle_hold_invoice(preimage)
        if "error" in res:
            return None, {"code": "OTHER", "message": res["error"]}

        return {}, None

    def _handle_cancel_hold_invoice(self, params: dict) -> tuple[dict | None, dict | None]:
        """
        cancel_hold_invoice response: {}
        Params: payment_hash (hex)
        """
        payment_hash = params.get("payment_hash")
        if not payment_hash:
            return None, {"code": "OTHER", "message": "payment_hash is required"}

        res = self.node.cancel_hold_invoice(payment_hash)
        if "error" in res:
            return None, {"code": "OTHER", "message": res["error"]}

        return {}, None

    # ------------------------------------------------------------------
    # Main Request Handler
    # ------------------------------------------------------------------

    async def handle_request(self, event_dict: dict):
        """Handle incoming NWC requests (Kind 23194)."""
        # client_pubkey = event_dict.get("pubkey")
        client_pubkey = self.client_pk
        request_id = event_dict.get("id")

        # 1. Rate Limiting
        now = time.time()
        last_requests = self.rate_limits.get(client_pubkey, [])
        last_requests = [t for t in last_requests if now - t < 60]
        if len(last_requests) >= 15:
            body = make_error_response("rate_limited", "RATE_LIMITED", "Too many requests. Retry in a few seconds.")
            await self.send_response(client_pubkey, request_id, body)
            return
        last_requests.append(now)
        self.rate_limits[client_pubkey] = last_requests

        method = "unknown"
        try:
            encrypted_content = event_dict.get("content", "")

            # 2. Decrypt
            content = nip04_decrypt(self.private_key, client_pubkey, encrypted_content)
            if not content:
                logger.warning(f"[{self.name}] Failed to decrypt content from {client_pubkey}")
                return

            data = json.loads(content)
            method = data.get("method", "unknown")
            params = data.get("params", {})
            print(f"[{self.name}] Request received | method={method} | from={client_pubkey[:8]}...")

            # 3. Dispatch
            result = None
            error = None

            if method == "get_info":
                result, error = self._handle_get_info(params)

            elif method == "get_balance":
                result, error = self._handle_get_balance(params)

            elif method == "make_invoice":
                result, error = self._handle_make_invoice(params,client_pubkey)

            elif method == "pay_invoice":
                # result, error = self._handle_pay_invoice(params,client_pubkey)
                result, error = await self._handle_pay_invoice(params, client_pubkey)


            elif method == "pay_keysend":
                result, error = self._handle_pay_keysend(params)

            elif method == "lookup_invoice":
                result, error = self._handle_lookup_invoice(params)

            elif method == "list_transactions":
                result, error = self._handle_list_payments(params)

                # result, error = self._handle_list_transactions(params)

            elif method == "list_payments":
                result, error = self._handle_list_payments(params)
            elif method == "make_hold_invoice":
                result, error = self._handle_make_hold_invoice(params, client_pubkey)
            elif method == "settle_hold_invoice":
                result, error = self._handle_settle_hold_invoice(params)
            elif method == "cancel_hold_invoice":
                result, error = self._handle_cancel_hold_invoice(params)

            else:
                error = {"code": "NOT_IMPLEMENTED", "message": f"Method '{method}' is not supported"}

            # 4. Build spec-compliant response
            if error:
                body = make_error_response(method, error["code"], error["message"])
            else:
                body = make_success_response(method, result)

            await self.send_response(client_pubkey, request_id, body)

            # 5. Send Notifications
            if not error:
                try:
                    if method in ("pay_invoice", "pay_keysend"):
                        payment_hash = result.get("payment_hash")

                        payer=self.client_pk

                        if payer:
                            # Build proper tx object
                            tx_obj = {
                                "payment_hash": payment_hash,
                                "amount": result.get("amount") or params.get("amount", 0),
                                "fees_paid": result.get("fees_paid", 0),
                                "created_at": int(time.time()),
                                "type": "outgoing"
                            }
                            await self.send_payment_sent_notification(payer, tx_obj)

                except Exception as notify_err:
                    logger.error(f"[{self.name}] Notification error: {notify_err}")
        except json.JSONDecodeError as e:
            logger.exception(f"[{self.name}] JSON parse error")
            body = make_error_response(method, "INTERNAL", f"JSON parse error: {str(e)}")
            await self.send_response(client_pubkey, request_id, body)

        except Exception as e:
            logger.exception(f"[{self.name}] Unhandled error in handle_request")
            body = make_error_response(method, "INTERNAL", str(e))
            await self.send_response(client_pubkey, request_id, body)

    # ------------------------------------------------------------------
    # Main Loop
    # ------------------------------------------------------------------

    async def run(self):
        """Connect to relay and listen for NWC requests."""
        print(f"[{self.name}] Connecting to relay: {self.relay_url}...")
        async with self.client:
            print(f"[{self.name}] Connected!")

            # Publish wallet info so clients discover capabilities
            await self.publish_wallet_info()

            # Start background listeners
            asyncio.create_task(self._listen_for_invoices())
            # asyncio.create_task(self._listen_for_payments())
            # asyncio.create_task(self._listen_for_htlc_events())
            # Subscribe to NWC requests (Kind 23194) addressed to our pubkey
            req_filter = Filter(kinds=[23194], p=[self.public_key])
            sub_id = await self.client.subscribe(req_filter)
            print(f"[{self.name}] Subscribed to NWC requests. sub_id={sub_id}")

            async for message in self.client.listen():
                if message[0] == "EVENT" and message[1] == sub_id:
                    event_data = message[2]
                    await self.handle_request(event_data)
                elif message[0] == "OK":
                    event_id = message[1]
                    success = message[2]
                    msg = message[3] if len(message) > 3 else ""
                    if not success:
                        logger.warning(f"[{self.name}] Relay rejected event {event_id[:8]}: {msg}")
                    else:
                        logger.debug(f"[{self.name}] Relay accepted event {event_id[:8]}")
                elif message[0] == "NOTICE":
                    print(f"[{self.name}] Relay Notice: {message[1]}")
                elif message[0] == "CLOSED":
                    logger.warning(f"[{self.name}] Subscription closed by relay: {message}")



# ------------------------------
# RUN
# ------------------------------
async def main():
    users = [
        {
            "name": "Alice",
            "nostr_sk": os.getenv("ALICE_WALLET_SERVICE_SK"),
            "nostr_pk": os.getenv("ALICE_WALLET_SERVICE_PK"),
            "client_pk": os.getenv("ALICE_CLIENT_PK"),
            "lnd": LNDNode(
                os.getenv("ALICE_LND_REST"),
                os.getenv("ALICE_MACAROON_PATH"),
                os.getenv("ALICE_TLS_CERT_PATH"),
                name="Alice"
            ),
        },
        {
            "name": "Bob",
            "nostr_sk": os.getenv("BOB_WALLET_SERVICE_SK"),
            "nostr_pk": os.getenv("BOB_WALLET_SERVICE_PK"),
            "client_pk": os.getenv("BOB_CLIENT_PK"),
            "lnd": LNDNode(
                os.getenv("BOB_LND_REST"),
                os.getenv("BOB_MACAROON_PATH"),
                os.getenv("BOB_TLS_CERT_PATH"),
                name="Bob"
            ),
        },
    ]

    bridges = []
    for u in users:
        if all([u["nostr_sk"], u["nostr_pk"], u["lnd"].rest_url]):
            bridge = NWCBridge(
                RELAY_URL,
                u["nostr_sk"],
                u["nostr_pk"],
                u["client_pk"],
                u["lnd"],
                name=u["name"],
            )
            bridges.append(bridge.run())
        else:
            print(f"Skipping {u['name']} due to missing configuration.")

    if not bridges:
        print("No bridges configured. Check your .env file.")
        return

    print(f"Starting {len(bridges)} NWC Bridge(s)...")
    await asyncio.gather(*bridges)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBridges stopped by user.")