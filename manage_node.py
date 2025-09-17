import requests
import codecs
import json
import base64
from requests.exceptions import RequestException

LND_REST = "https://127.0.0.1:8081"
TLS_CERT_PATH = "/Users/safwanonakkal/.polar/networks/5/volumes/lnd/alice/tls.cert"
MACAROON_PATH = "/Users/safwanonakkal/.polar/networks/5/volumes/lnd/alice/data/chain/bitcoin/regtest/admin.macaroon"
BACKUP_FILE = 'channel_backup.json'

with open(MACAROON_PATH, "rb") as f:
    macaroon = codecs.encode(f.read(), 'hex').decode()

HEADERS = {"Grpc-Metadata-macaroon": macaroon}
CERT = TLS_CERT_PATH


def list_peers():
    """
    List all connected peers with alias and pub_key

    Returns:
        list: List of peer info dictionaries with "alias" and "pub_key" keys.
    """
    try:
        r = requests.get(f"{LND_REST}/v1/peers", headers=HEADERS, verify=CERT)
        peers = r.json().get("peers", [])
        result = []
        for peer in peers:
            pub_key = peer["pub_key"]
            node_info = requests.get(f"{LND_REST}/v1/graph/node/{pub_key}", headers=HEADERS, verify=CERT)
            alias = node_info.json().get("node", {}).get("alias", "unknown")
            result.append({"alias": alias, "pub_key": pub_key})
        print("Current peers:", result)
        return result
    except Exception as e:
        print(f"Error listing peers: {e}")
        return []


def create_channel(pubkey, local_amt_sats, private=False):
    """
    Create a new channel with the given peer pubkey and local funding amount.

    Args:
        pubkey (str): The pubkey of the peer to open the channel with.
        local_amt_sats (int): The local funding amount in satoshis.
        private (bool, optional): Whether the channel should be private. Defaults to False.

    Returns:
        dict: The response from the LND node containing the channel info.
    """
    try:
        data = {"node_pubkey_string": pubkey, "local_funding_amount": str(local_amt_sats), "private": private}
        r = requests.post(f"{LND_REST}/v1/channels", headers=HEADERS, json=data, verify=CERT)
        print("Open channel response:", r.json())
        return r.json()
    except Exception as e:
        print(f"Error creating channel: {e}")


def get_balance():
    try:
        r = requests.get(f"{LND_REST}/v1/balance/blockchain", headers=HEADERS, verify=CERT)
        print("Wallet balance:", r.json())
        return r.json()
    except Exception as e:
        print(f"Error fetching wallet balance: {e}")


def channel_balance(selected_channel, selected_peer):
    """
    Print the channel balance for the given peer and channel.

    Args:
        selected_channel (dict): The channel to fetch the balance for.
        selected_peer (dict): The peer to fetch the balance for.

    Raises:
        Exception: If there is an error fetching the channel balance.
    """
    try:
        print(f"\nChannel balance for {selected_peer['alias']} ({selected_channel['channel_point']}):")
        print("local_balance:", selected_channel["local_balance"])
        print("remote_balance:", selected_channel["remote_balance"])
    except Exception as e:
        print(f"Error fetching channel balance: {e}")


def create_invoice(value_sat, memo="Test Invoice"):
    """
    Create a new invoice with the given value in satoshis and memo.

    Args:
        value_sat (int): The value of the invoice in satoshis.
        memo (str, optional): The memo of the invoice. Defaults to "Test Invoice".

    Returns:
        dict: The response from the LND node containing the invoice info.

    Raises:
        Exception: If there is an error creating the invoice.
    """
    try:
        data = {"value": value_sat, "memo": memo}
        r = requests.post(f"{LND_REST}/v1/invoices", headers=HEADERS, json=data, verify=CERT)
        print("Invoice:", r.json())
        return r.json()
    except Exception as e:
        print(f"Error creating invoice: {e}")


def settle_invoice(invoice):
    """
    Settle an invoice by sending a payment request to the LND node.

    Args:
        invoice (dict): The invoice to settle.

    Raises:
        Exception: If there is an error settling the invoice.
    """
    try:
        data = {"payment_request": invoice}
        r = requests.post(f"{LND_REST}/v1/channels/transactions", headers=HEADERS, json=data, verify=CERT)
        print(r.json())
    except Exception as e:
        print(f"Error settling invoice: {e}")


def list_channels():
    """
    List all open channels.

    Returns:
        list: List of channel info dictionaries with "channel_point", "capacity", "remote_pubkey", etc. keys.
    """
    try:
        r = requests.get(f"{LND_REST}/v1/channels", headers=HEADERS, verify=CERT)
        print("Current channels:", r.json())
        return r.json().get("channels", [])
    except Exception as e:
        print(f"Error listing channels: {e}")
        return []


def close_channel(selected_channel, selected_peer):
    """
    Close an open channel with the given peer and channel.

    Args:
        selected_channel (dict): The channel to close.
        selected_peer (dict): The peer to close the channel with.

    Raises:
        Exception: If there is an error closing the channel.
    """
    try:
        print(f"\nClosing channel {selected_channel['channel_point']} with {selected_peer['alias']}...")
        force = input("Force close? (y/n): ").lower() == "y"
        channel_point = selected_channel["channel_point"].replace(":", "/")
        url = f"{LND_REST}/v1/channels/{channel_point}"
        if force:
            url += "?force=true"
        r = requests.delete(url, headers=HEADERS, verify=CERT, stream=True)
        for raw_response in r.iter_lines():
            if raw_response:
                print(json.loads(raw_response))
    except Exception as e:
        print(f"Error closing channel: {e}")


def channel_flow():
    """
    Interactive flow: select peer -> channel -> close.

    Returns:
        tuple: A tuple containing the selected peer and channel info dictionaries.
    """
    try:
        peers = list_peers()
        if not peers:
            print("No connected peers.")
            return None, None
        print("\nSelect a peer:")
        for i, peer in enumerate(peers, 1):
            print(f"{i}. {peer['alias']} ({peer['pub_key']})")
        peer_choice = int(input("Enter peer number: ")) - 1
        if peer_choice not in range(len(peers)):
            print("Invalid choice.")
            return None, None
        selected_peer = peers[peer_choice]
        print(f"\nSelected peer: {selected_peer['alias']}")
        all_channels = list_channels()
        peer_channels = [ch for ch in all_channels if ch["remote_pubkey"] == selected_peer["pub_key"]]
        if not peer_channels:
            print("No channels found with this peer.")
            return None, None
        print("\nSelect a channel:")
        for i, ch in enumerate(peer_channels, 1):
            print(f"{i}. ChannelPoint: {ch['channel_point']}, Capacity: {ch['capacity']}")
        chan_choice = int(input("Enter channel number: ")) - 1
        if chan_choice not in range(len(peer_channels)):
            print("Invalid choice.")
            return None, None
        return selected_peer, peer_channels[chan_choice]
    except Exception as e:
        print(f"Error in channel flow: {e}")
        return None, None


def node_backup():
    """
    Back up the node state.

    This function fetches the channel backup from the LND node and writes it to a file.
    It returns the backup data as a JSON object.

    Returns:
        dict: The channel backup data as a JSON object.

    Raises:
        Exception: If there is an error backing up the node state.
    """
    try:
        r = requests.get(f"{LND_REST}/v1/channels/backup", headers=HEADERS, verify=CERT)
        backup_data = r.json()
        with open(BACKUP_FILE, 'w') as f:
            json.dump(backup_data, f, indent=4)
        print("Backup:", backup_data)
        return backup_data
    except Exception as e:
        print(f"Error backing up node: {e}")


def restore_node_from_backup():
    """
    Restore the node state from a backup file.

    This function reads the channel backup from a file and sends it to the LND node to restore the node state.
    It returns the restore result as a JSON object.

    Returns:
        dict: The restore result as a JSON object.

    Raises:
        Exception: If there is an error restoring the node state.
    """
    try:
        with open(BACKUP_FILE, 'r') as f:
            backup_data = json.load(f)
        if 'multi_chan_backup' in backup_data and backup_data['multi_chan_backup']:
            payload = backup_data['multi_chan_backup']
            r = requests.post(f"{LND_REST}/v1/channels/restore", headers=HEADERS, json=payload, verify=CERT)
            print("Restore result:", r.json())
            return r.json()
        print("No multi-channel backup found.")
        return None
    except Exception as e:
        print(f"Error restoring node: {e}")


def custom_message(selected_channel, selected_peer):
    """
    Send a custom message to a peer.

    This function sends a custom message to a peer via the LND node's custom message endpoint.
    The function takes a selected channel and peer as arguments, and prompts the user to enter a custom message.
    The function then sends the message to the peer via the LND node and returns the response from the LND node as a JSON object.

    Args:
        selected_channel (dict): The channel to send the custom message through.
        selected_peer (dict): The peer to send the custom message to.

    Returns:
        dict: The response from the LND node as a JSON object.

    Raises:
        Exception: If there is an error sending the custom message.
    """
    try:
        print(f"\nSending custom message to {selected_peer['alias']}...")
        peer_pubkey_hex = selected_peer["pub_key"]
        peer_bytes = bytes.fromhex(peer_pubkey_hex)
        peer_b64 = base64.b64encode(peer_bytes).decode('utf-8')
        message = input("Enter your custom message: ")
        data_b64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
        msg_type = 32768
        data = {'peer': peer_b64, 'type': msg_type, 'data': data_b64}
        r = requests.post(f"{LND_REST}/v1/custommessage", headers=HEADERS, json=data, verify=CERT)
        print("Custom message response:", r.json())
        return r.json()
    except Exception as e:
        print(f"Error sending custom message: {e}")


def subscribe_msgs():
    """
    Subscribe to custom messages sent to this node.

    This function subscribes to the custom message endpoint of the LND node and prints any received custom messages.
    The function takes no arguments and returns no value.

    Raises:
        Exception: If there is an error subscribing to custom messages.
    """
    try:
        r = requests.get(f"{LND_REST}/v1/custommessage/subscribe", stream=True, headers=HEADERS, verify=CERT)
        for raw_response in r.iter_lines():
            if raw_response:
                json_response = json.loads(raw_response)
                result = json_response['result']
                peer_decoded = base64.b64decode(result['peer']).hex()
                data_decoded = base64.b64decode(result['data']).decode('utf-8')
                print(f"Received message from {peer_decoded}: {data_decoded}")
    except Exception as e:
        print(f"Error subscribing to messages: {e}")


def get_nodeinfo():
    """
    Fetch node information from the LND node.

    This function fetches information about the LND node and prints it to the console.
    The function takes no arguments and returns a JSON object containing the node information.

    Returns:
        dict: The node information as a JSON object.

    Raises:
        Exception: If there is an error fetching the node information.
    """
    try:
        r = requests.get(f"{LND_REST}/v1/getinfo", headers=HEADERS, verify=CERT)
        node_info = r.json()
        print("Node Info:", json.dumps(node_info, indent=2))
        return node_info
    except Exception as e:
        print(f"Error fetching node info: {e}")


if __name__ == "__main__":
    try:
        print("1. Open channel\n2. Balance\n3. Invoice\n4. Close Channel\n5. List Peers\n6. List Channels\n7. Wallet Balance\n8. Node Backup\n9. Restore Node from Backup\n10. Custom Message\n11. Node Info")
        choice = input("Enter your choice: ")

        if choice == "1":
            pubkey = input("Enter the public key of the node you want to connect to: ")
            local_amt_sats = input("Enter the local amount in sats: ")
            create_channel(pubkey, local_amt_sats)
        elif choice == "2":
            selected_peer, selected_channel = channel_flow()
            if selected_peer and selected_channel:
                channel_balance(selected_channel, selected_peer)
        elif choice == "3":
            print("1. Create invoice\n2. Settle invoice")
            sub_choice = input("Enter your choice: ")
            if sub_choice == "1":
                value = input("Enter value: ")
                memo = input("Enter memo: ")
                create_invoice(value, memo)
            elif sub_choice == "2":
                invoice = input("Enter invoice: ")
                settle_invoice(invoice)
        elif choice == "4":
            selected_peer, selected_channel = channel_flow()
            if selected_peer and selected_channel:
                close_channel(selected_channel, selected_peer)
        elif choice == "5":
            list_peers()
        elif choice == "6":
            list_channels()
        elif choice == "7":
            get_balance()
        elif choice == "8":
            node_backup()
        elif choice == "9":
            restore_node_from_backup()
        elif choice == "10":
            selected_peer, selected_channel = channel_flow()
            if selected_peer and selected_channel:
                custom_message(selected_channel, selected_peer)
        elif choice == "11":
            get_nodeinfo()
    except Exception as e:
        print(f"Unexpected error: {e}")
