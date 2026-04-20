import requests
import codecs
import json
import base64
import logging
import hashlib
import os
import httpx
import asyncio

logger = logging.getLogger(__name__)

class LNDNode:
    def __init__(self, rest_url, macaroon_path, tls_cert_path, name="LND"):
        self.rest_url = rest_url.rstrip("/")
        self.cert = tls_cert_path
        self.name = name
        
        try:
            with open(macaroon_path, "rb") as f:
                self.macaroon = codecs.encode(f.read(), "hex").decode()
            self.headers = {"Grpc-Metadata-macaroon": self.macaroon}
        except Exception as e:
            logger.error(f"Failed to load macaroon from {macaroon_path}: {e}")
            raise

    def get_info(self):
        try:
            r = requests.get(f"{self.rest_url}/v1/getinfo", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error fetching node info: {e}")
            return {"error": str(e)}

    def get_balance(self):
        try:
            r = requests.get(f"{self.rest_url}/v1/balance/blockchain", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error fetching balance: {e}")
            return {"error": str(e)}

    def create_invoice(self, value_sat, memo="NWC Invoice"):
        try:
            data = {"value": str(value_sat), "memo": memo}
            r = requests.post(f"{self.rest_url}/v1/invoices", headers=self.headers, json=data, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error creating invoice: {e}")
            return {"error": str(e)}

    # def settle_invoice(self, payment_request):
    #     try:
    #         data = {"payment_request": payment_request}
    #         r = requests.post(f"{self.rest_url}/v1/channels/transactions", headers=self.headers, json=data, verify=self.cert)
    #         r.raise_for_status()
    #         return r.json()
    #     except Exception as e:
    #         logger.error(f"Error settling invoice: {e}")
    #         return {"error": str(e)}

    # async def settle_invoice_v2(self,payment_request: str):
        # """
        # Pay a BOLT11 invoice using LND's SendPaymentV2 streaming API.
        # POST /v2/router/send
        # """
        # try:
        #     data = {
        #         "payment_request": payment_request,
        #         "fee_limit_sat": "10",
        #         "timeout_seconds": 60
        #     }

        #     r = requests.post(
        #         f"{self.rest_url}/v2/router/send",
        #         headers=self.headers,
        #         json=data,
        #         verify=self.cert,
        #         stream=True                         # Required: endpoint streams status updates
        #     )
        #     r.raise_for_status()
        #     for raw_line in r.iter_lines():
        #                 if not raw_line:
        #                     continue

        #                 update = json.loads(raw_line)
        #                 result = update.get("result", update)   # REST wraps response in {"result": {...}}
        #                 status = result.get("status", "UNKNOWN")

        #                 print(f"  ↳ Status: {status}")

        #                 if status == "SUCCEEDED":
        #                     return {"success": True, "result": result}

        #                 elif status == "FAILED":
        #                     reason = result.get("failure_reason", "UNKNOWN_REASON")
        #                     return {"success": False, "error": f"Payment failed: {reason}", "result": result}

        #     return {"success": False, "error": "Stream ended without a final status."}

        # except requests.exceptions.HTTPError as e:
        #     try:
        #         error_body = e.response.json()
        #     except Exception:
        #         error_body = e.response.text
        #         return {"success": False, "error": error_body}

        # except Exception as e:
        #     return {"success": False, "error": str(e)}           
  
    
    async def settle_invoice_v2(self, payment_request: str):
        """
        Pay a BOLT11 invoice using LND's SendPaymentV2 streaming API.
        POST /v2/router/send
        """
        data = {
            "payment_request": payment_request,
            "fee_limit_sat": "10",
            "timeout_seconds": 60
        }

        timeout = httpx.Timeout(connect=5.0, read=65.0, write=10.0, pool=10.0)

        try:
            async with httpx.AsyncClient(
                verify=self.cert,
                timeout=timeout,
                headers=self.headers,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self.rest_url}/v2/router/send",
                    json=data,
                ) as response:
                    response.raise_for_status()

                    last_status = None
                    last_result = None

                    queue = asyncio.Queue()

                    async def read_stream(res, q):
                        try:
                            async for line in res.aiter_lines():
                                if line:
                                    await q.put(line)
                        except Exception as e:
                            logger.debug(f"Stream reader encountered error: {e}")
                        finally:
                            await q.put(None)  # Sentinel for end of stream

                    reader_task = asyncio.create_task(read_stream(response, queue))

                    try:
                        last_result = None
                        # Use a 5-second grace period to decide if it's a quick success or a hold invoice
                        grace_deadline = asyncio.get_event_loop().time() + 5.0
                        yielded_initial = False

                        while True:
                            now = asyncio.get_event_loop().time()
                            try:
                                # If we haven't yielded initial status and still in grace period, wait with timeout
                                if not yielded_initial and now < grace_deadline:
                                    try:
                                        raw_line = await asyncio.wait_for(queue.get(), timeout=grace_deadline - now)
                                    except asyncio.TimeoutError:
                                        # Grace period expired without success/failure. 
                                        # Yield IN_FLIGHT if we have a result.
                                        if last_result and not yielded_initial:
                                            yield {
                                                "success": True,
                                                "in_flight": True,
                                                "error": "payment is in transition",
                                                "result": last_result,
                                            }
                                            yielded_initial = True
                                        continue # Re-check 'now < grace_deadline'
                                else:
                                    # Past grace period or initial yielded; just get next from queue
                                    raw_line = await queue.get()
                            except Exception as e:
                                logger.error(f"Error reading from stream queue: {e}")
                                break

                            if raw_line is None:  # Sentinel reached
                                break

                            update = json.loads(raw_line)
                            result = update.get("result", update)
                            status = result.get("status", "UNKNOWN")
                            last_result = result

                            logger.info(f"[{self.name}] payment status: {status}")

                            if status == "SUCCEEDED":
                                yield {"success": True, "result": result}
                                return

                            elif status == "FAILED":
                                reason = result.get("failure_reason", "UNKNOWN_REASON")
                                yield {
                                    "success": False,
                                    "error": f"Payment failed: {reason}",
                                    "result": result,
                                }
                                return
                            
                            elif status == "IN_FLIGHT":
                                # If we are past the grace period, yield the status
                                if asyncio.get_event_loop().time() >= grace_deadline:
                                    if not yielded_initial:
                                        yield {
                                            "success": True,
                                            "in_flight": True,
                                            "error": "payment is in transition",
                                            "result": last_result,
                                        }
                                        yielded_initial = True

                        if not yielded_initial:
                            yield {
                                "success": False,
                                "error": "Stream ended without a final status."
                            }
                        return
                    finally:
                        reader_task.cancel()

        except httpx.HTTPStatusError as e:
            try:
                await e.response.aread()
                error_body = e.response.json()
            except Exception:
                try:
                    error_body = e.response.text
                except Exception:
                    error_body = str(e)

            yield {"success": False, "error": error_body}

        except Exception as e:
            yield {"success": False, "error": str(e)}
    
    
    
    def list_channels(self):
        try:
            r = requests.get(f"{self.rest_url}/v1/channels", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json().get("channels", [])
        except Exception as e:
            logger.error(f"Error listing channels: {e}")
            return []

    def get_channel_balance(self):
        try:
            r = requests.get(f"{self.rest_url}/v1/balance/channels", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error fetching channel balance: {e}")
            return {"error": str(e)}

    def list_invoices(self, pending_only=False, index_offset=0, num_max_invoices=0, reversed=False):
        try:
            params = {
                "pending_only": pending_only,
                "index_offset": index_offset,
                "num_max_invoices": num_max_invoices,
                "reversed": reversed,
            }
            r = requests.get(f"{self.rest_url}/v1/invoices", headers=self.headers, params=params, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error listing invoices: {e}")
            return {"error": str(e)}

    def list_payments(self, include_incomplete=False, index_offset=0, max_payments=0, reversed=True):
        try:
            import requests

            def to_int(value, default=0):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return default

            def get_time(item, kind):
                # use settle time for received invoices when available
                if kind == "incoming":
                    return to_int(item.get("settle_date")) or to_int(item.get("creation_date"))
                # for outgoing payments prefer ns field, fallback to seconds
                return to_int(str(item.get("creation_time_ns", "0"))[:10]) or to_int(item.get("creation_date"))

            combined = []

            payment_params = {
                "include_incomplete": str(include_incomplete).lower(),
                "index_offset": index_offset,
                "max_payments": max_payments,
                "reversed": str(reversed).lower(),
            }

            pay_resp = requests.get(
                f"{self.rest_url}/v1/payments",
                headers=self.headers,
                params=payment_params,
                verify=self.cert,
            )
            pay_resp.raise_for_status()
            pay_data = pay_resp.json()

            for p in pay_data.get("payments", []):
                combined.append({
                    "type": "outgoing",
                    "payment_hash": p.get("payment_hash"),
                    "value_sat": p.get("value_sat") or p.get("value"),
                    "fee_sat": p.get("fee_sat") or p.get("fee"),
                    "status": p.get("status"),
                    "creation_date": p.get("creation_date"),
                    "creation_time_ns": p.get("creation_time_ns"),
                    "time_sort": get_time(p, "outgoing"),
                    "payment_request": p.get("payment_request"),
                    "raw_data": p,
                })

            invoice_params = {
                "pending_only": "false",
                "index_offset": 0,
                "num_max_invoices": max_payments,
                "reversed": str(reversed).lower(),
            }

            inv_resp = requests.get(
                f"{self.rest_url}/v1/invoices",
                headers=self.headers,
                params=invoice_params,
                verify=self.cert,
            )
            inv_resp.raise_for_status()
            inv_data = inv_resp.json()

            for inv in inv_data.get("invoices", []):
                if inv.get("state") != "SETTLED":
                    continue

                combined.append({
                    "type": "incoming",
                    "payment_hash": inv.get("r_hash"),
                    "value_sat": to_int(inv.get("amt_paid_sat") or inv.get("value")),
                    "fee_sat": 0,
                    "status": inv.get("state"),
                    "creation_date": inv.get("creation_date"),
                    "settle_date": inv.get("settle_date"),
                    "time_sort": get_time(inv, "incoming"),
                    "payment_request": inv.get("payment_request"),
                    "memo": inv.get("memo"),
                    "raw_data": inv,
                })

            combined.sort(key=lambda x: x["time_sort"], reverse=True)

            return {
                "payments": combined,
                "first_index_offset": pay_data.get("first_index_offset", "0"),
                "last_index_offset": pay_data.get("last_index_offset", "0"),
                "total_num_payments": str(len(combined)),
            }

        except Exception as e:
            logger.error(f"Error listing payments: {e}")
            return {"error": str(e)}

    def keysend(self, dest_pubkey, amount_sat, fee_limit_sat=1000, timeout_seconds=60):
        try:

            def hex_to_b64(hex_str):
                return base64.b64encode(bytes.fromhex(hex_str)).decode("utf-8")

            def bytes_to_b64(value):
                return base64.b64encode(value).decode("utf-8")

            preimage = os.urandom(32)
            payment_hash_bytes = hashlib.sha256(preimage).digest()

            dest_custom_records = {
                "5482373484": bytes_to_b64(preimage)
            }

            payload = {
                "dest": hex_to_b64(dest_pubkey),
                "amt": int(amount_sat),
                "payment_hash": bytes_to_b64(payment_hash_bytes),
                "dest_custom_records": dest_custom_records,
                "fee_limit_sat": int(fee_limit_sat),
                "timeout_seconds": int(timeout_seconds),
                "no_inflight_updates": False,
            }

            r = requests.post(
                f"{self.rest_url}/v2/router/send",
                headers=self.headers,
                json=payload,
                stream=True,
                verify=self.cert,
                timeout=timeout_seconds + 10,
            )

            if not r.ok:
                return {
                    "success": False,
                    "status_code": r.status_code,
                    "error_body": r.text,
                }

            updates = []
            final_update = None

            for line in r.iter_lines():
                if not line:
                    continue
                update = json.loads(line.decode("utf-8"))
                updates.append(update)
                
                # Handle potential "result" wrapping from gRPC-gateway streams
                inner = update.get("result", update)
                final_update = inner

                if inner.get("status") in ["SUCCEEDED", "FAILED"]:
                    break

            return {
                "success": True,
                "payment_hash_hex": payment_hash_bytes.hex(),
                "payment": final_update,
                "updates": updates,
            }

        except Exception as e:
            logger.error(f"Error sending keysend payment: {e}")
            return {"success": False, "error": str(e)}
    
    def lookup_invoice(self, invoice):
        try:
            r = requests.get(f"{self.rest_url}/v1/payreq/{invoice}", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error looking up invoice: {e}")
            return {"error": str(e)}

    def lookup_payment(self, payment_hash):
        try:
            r = requests.get(f"{self.rest_url}/v1/payments/{payment_hash}", headers=self.headers, verify=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error looking up payment {payment_hash}: {e}")
            return {"error": str(e)}

    def create_hold_invoice(self, amount_sat, payment_hash, description="", expiry=3600):
        try:
            if isinstance(payment_hash, str):
                payment_hash = bytes.fromhex(payment_hash)
            
            payment_hash_b64 = base64.b64encode(payment_hash).decode("utf-8")
            
            payload = {
                "value": int(amount_sat),
                "hash": payment_hash_b64,
                "memo": description,
                "expiry": int(expiry),
            }

            r = requests.post(
                f"{self.rest_url}/v2/invoices/hodl",
                headers=self.headers,
                json=payload,
                verify=self.cert,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error creating hold invoice: {e}")
            return {"error": str(e)}

    def settle_hold_invoice(self, preimage):
        try:
            if isinstance(preimage, str):
                preimage = bytes.fromhex(preimage)
            
            preimage_b64 = base64.b64encode(preimage).decode("utf-8")
            
            payload = {
                "preimage": preimage_b64,
            }

            r = requests.post(
                f"{self.rest_url}/v2/invoices/settle",
                headers=self.headers,
                json=payload,
                verify=self.cert,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error settling hold invoice: {e}")
            return {"error": str(e)}

    def cancel_hold_invoice(self, payment_hash):
        try:
            if isinstance(payment_hash, str):
                payment_hash = bytes.fromhex(payment_hash)
            
            payment_hash_b64 = base64.b64encode(payment_hash).decode("utf-8")
            
            payload = {
                "payment_hash": payment_hash_b64,
            }

            r = requests.post(
                f"{self.rest_url}/v2/invoices/cancel",
                headers=self.headers,
                json=payload,
                verify=self.cert,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"Error canceling hold invoice: {e}")
            return {"error": str(e)}
    
    def subscribe_invoices(self):
        """
        Subscribe to invoice updates.
        Returns a generator of invoice objects.
        """
        try:
            r = requests.get(
                f"{self.rest_url}/v1/invoices/subscribe",
                headers=self.headers,
                stream=True,
                params={"is_keysend": True},
                verify=self.cert,
            )
            r.raise_for_status()
            # logger.info(f"[{self.name}] LND invoice subscription established: {r}")
            
            for line in r.iter_lines():
                if line:
                    update = json.loads(line.decode("utf-8"))
                    # LND REST stream wraps results in a "result" field
                    invoice = update.get("result", update)
                    # logger.info(f"[{self.name}] LND Invoice update received: {invoice}")
                    yield invoice
        except Exception as e:
            logger.error(f"Error subscribing to invoices: {e}")
            return

    async def subscribe_payments(self):
        """
        Subscribe to background payment updates.
        GET /v2/router/payments
        """
        timeout = httpx.Timeout(connect=5.0, read=None, write=10.0, pool=10.0)
        try:
            async with httpx.AsyncClient(
                verify=self.cert,
                timeout=timeout,
                headers=self.headers,
            ) as client:
                async with client.stream(
                    "GET",
                    f"{self.rest_url}/v2/router/payments"
                    # params={"no_inflight_updates": False}
                ) as response:
                    response.raise_for_status()

                    async for raw_line in response.aiter_lines():
                        if not raw_line:
                            continue

                        update = json.loads(raw_line)
                        payment = update.get("result", update)
                        logger.info(f"[{self.name}] LND Payment update from subscribe_payments: {payment['status'], payment['value_sat']}")
                        yield payment
        except Exception as e:
            logger.error(f"[{self.name}] Error subscribing to payments: {e}")
            return
    
    def subscribe_htlcs(self):
        """
        Subscribe to HTLC events (captures keysend payments).
        """
        url = f"{self.rest_url}/v2/router/htlcevents"
        try:
            r = requests.get(
                url,
                headers=self.headers,
                stream=True,
                verify=self.cert,
            )
            r.raise_for_status()

            for line in r.iter_lines():
                if not line:
                    continue

                try:
                    update = json.loads(line.decode("utf-8"))
                    # LND REST stream wraps results in a "result" field
                    event = update.get("result", update)

                    event_type = event.get("event_type")

                    # We only care about settled incoming HTLCs
                    if event_type == "RECEIVE" :
                        htlc = event["settle_event"]
                        preimage = htlc.get("preimage")
                        custom_records = htlc.get("custom_records", {})

                        # Extract amount if available from incoming_htlc field
                        incoming = event.get("incoming_htlc", {})
                        amount_msat = int(incoming.get("amt_msat", 0))
                        amount_sat = amount_msat // 1000

                        yield {
                            "type": "keysend",
                            "preimage": preimage,
                            "amount_sat": amount_sat,
                            "timestamp": event.get("timestamp_ns"),
                            "custom_records": custom_records,
                            "raw": event
                        }

                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error in HTLC stream: {e}")
                except Exception as e:
                    # Logic error or missing fields, skip this event
                    continue

        except Exception as e:
            logger.error(f"Error subscribing to HTLC events: {e}")

    async def subscribe_single_invoice(self, r_hash_hex: str):
        """
        Subscribe to updates for a single invoice.
        GET /v2/invoices/subscribe/{r_hash}
        """
        import base64
        r_hash_bytes = bytes.fromhex(r_hash_hex)
        r_hash_b64 = base64.urlsafe_b64encode(r_hash_bytes).decode('utf-8')
        
        timeout = httpx.Timeout(connect=5.0, read=None, write=10.0, pool=10.0)
        url = f"{self.rest_url}/v2/invoices/subscribe/{r_hash_b64}"

        
        try:
            async with httpx.AsyncClient(
                verify=self.cert,
                timeout=timeout,
                headers=self.headers,
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
            logger.error(f"[{self.name}] Error subscribing to invoice {r_hash_hex}: {e}")
            return