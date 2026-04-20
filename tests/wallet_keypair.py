from nostr_tools import generate_keypair

wallet_service_secret, wallet_service_pub = generate_keypair()
print("Wallet Service Secret: ", wallet_service_secret)
print("Wallet Service Pub: ", wallet_service_pub)

client_secret, client_pub = generate_keypair()
print("Client Secret: ", client_secret)
print("Client Pub: ", client_pub)

# from nostr.key import PrivateKey
# print(PrivateKey().hex())
# print(PrivateKey().public_key.hex())