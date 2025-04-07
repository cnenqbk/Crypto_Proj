import os
import hashlib
import ecdsa
import base58
import secrets

# Functions
def generate_new_keypair():
    private_key = secrets.token_bytes(32)
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    compressed_public_key = compress_public_key(public_key)
    btc_address = public_key_to_address(compressed_public_key)
    wif = private_key_to_wif_compressed(private_key)
    raw_private_key = private_key_to_raw_format(private_key)
    return private_key.hex(), raw_private_key, compressed_public_key.hex(), btc_address, wif

def private_key_to_raw_format(private_key):
    return private_key.hex()

def private_key_to_wif_compressed(private_key):
    extended_key = b'\x80' + private_key + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    return wif

def private_key_to_compressed_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    compressed_public_key = compress_public_key(public_key)
    return compressed_public_key

def compress_public_key(public_key):
    x = public_key[1:33]
    y = public_key[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def public_key_to_address(compressed_public_key):
    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    address_bytes = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    binary_address = address_bytes + checksum
    return base58.b58encode(binary_address).decode('utf-8')

def check_private_key(private_key):
    wif = private_key_to_wif_compressed(private_key.to_bytes(32, 'big'))
    compressed_public_key = private_key_to_compressed_public_key(private_key)
    btc_address = public_key_to_address(compressed_public_key)
    raw_private_key = private_key_to_raw_format(private_key.to_bytes(32, 'big'))
    return compressed_public_key.hex(), btc_address, raw_private_key, wif

def check_compressed_public_key(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 33:
        raise ValueError("Invalid compressed public key length")
    btc_address = public_key_to_address(public_key_bytes)
    return btc_address

if __name__ == "__main__":
    while True:
        try:
            option = input("Choose an option: (1) Check Private Key (2) Check Compressed Public Key (3) Generate New Bitcoin Address: ").strip()
            print("-" * 50)
            if option == '1':
                private_key_input = input("Enter the private key (hex): ").strip()
                if len(private_key_input) != 64 or not all(c in '0123456789abcdefABCDEF' for c in private_key_input):
                    print("Invalid private key format. Must be 64 hex characters.")
                else:
                    private_key = int(private_key_input, 16)
                    pub_key, addr, raw_private_key, wif = check_private_key(private_key)
                    print(f"Private Key:           {hex(private_key)[2:]}")
                    print(f"Raw Private Key:    {raw_private_key}")
                    print(f"Compressed Public Key: {pub_key}")
                    print(f"Bitcoin Address:       {addr}")
                    print(f"Compressed WIF:        {wif}")
            elif option == '2':
                compressed_public_key = input("Enter compressed public key: ").strip()
                if len(compressed_public_key) != 66 or not all(c in '0123456789abcdefABCDEF' for c in compressed_public_key):
                    print("Invalid compressed public key format. Must be 66 hex characters.")
                else:
                    btc_address = check_compressed_public_key(compressed_public_key)
                    print(f"Bitcoin Address: {btc_address}")
            elif option == '3':
                private_key, raw_private_key, compressed_public_key, btc_address, wif = generate_new_keypair()
                print(f"Private Key:           {private_key}")
                print(f"Raw Private Key:    {raw_private_key}")
                print(f"Compressed Public Key: {compressed_public_key}")
                print(f"Bitcoin Address:       {btc_address}")
                print(f"Compressed WIF:        {wif}")
            else:
                print("Invalid option selected.")
        except Exception as e:
            print(f"An error occurred: {e}")
        print("-" * 50)
        cont = input("Do you want to continue? (yes/no): ").strip().lower()
        if cont != 'yes':
            print("Exiting program.")
            break
