# NWC Polar Bridge

A robust Python-based Nostr Wallet Connect (NIP-47) bridge for LND nodes, featuring multi-node support, real-time notifications, and advanced handling for HODL invoices. Optimized for Polar regtest environments.

## Features

- **Full NIP-47 Support**: `pay_invoice`, `pay_keysend`, `make_invoice`, `get_balance`, `get_info`, and more.
- **Real-time Notifications**: Subscriptions for `payment_received`, `payment_sent`, and `hold_invoice_accepted`.
- **HODL Invoice Management**: Specialized tracking and state-aware notifications for hold invoices.
- **Multi-Bridge Support**: Simultaneously manage multiple wallet services (e.g., Alice, Bob).
- **Polar Integration**: Pre-configured for easy use with Polar's Lightning Network simulation environment.

## Prerequisites

- [Polar](https://lightningpolar.com/) (running a local Lightning Network)
- Python 3.10+
- LND Nodes (Alice, Bob, etc.)

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/safwankamar/nwc_bridge_polar.git
   cd nwc_bridge_polar
   ```

2. **Install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Create a `.env` file based on the provided configuration (see `.env.example` if available, or populate based on your Polar node credentials).

4. **Run the Bridge:**
   ```bash
   python wallet_bridge.py
   ```

## Supported Methods (NIP-47)
- `pay_invoice`
- `pay_keysend`
- `get_balance`
- `get_info`
- `make_invoice`
- `lookup_invoice`
- `list_transactions`
- `list_payments`

## License
MIT
