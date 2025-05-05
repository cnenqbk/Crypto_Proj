import os
import random
import requests
import hashlib
import ecdsa
import base58
import time
import sys
import psutil
import math
from multiprocessing import Pool, Value, Manager, Lock, Process, cpu_count
from colorama import Fore, Style, init
init()

# Target Bitcoin address
TARGET_BTC_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# Private key range
PRIVATE_KEY_MIN = 0x400000000000000000
PRIVATE_KEY_MAX = 0x7FFFFFFFFFFFFFFFFF

# Config
SUB_RANGE_SIZE = 2**20  # 1,048,576 keys per sub-range
found = Value('b', False)
PRINT_LOCK = Lock()

# Utility functions
def compress_public_key(public_key):
    x = public_key[1:33]
    y = public_key[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def check_btc_balance(address):
    try:
        response = requests.get(f"https://blockchain.info/q/addressbalance/{address}")
        response.raise_for_status()
        satoshis = int(response.text)
        return satoshis / 100000000
    except Exception as e:
        with PRINT_LOCK:
            print(f"\nError checking balance: {e}")
        return None

def get_cpu_info():
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return (physical, logical) if physical else (logical, logical)
    except:
        logical = cpu_count()
        return (logical, logical)

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address(compressed_public_key):
    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    address_bytes = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    return base58.b58encode(address_bytes + checksum).decode('utf-8')

def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key.to_bytes(32, 'big') + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode('utf-8')

def format_time(seconds):
    hrs, rem = divmod(int(seconds), 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs:02}:{mins:02}:{secs:02}"

def print_keys_checked(keys_checked, start_time):
    while not found.value:
        time.sleep(1)
        elapsed_time = time.time() - start_time
        keys_per_second = keys_checked.value / elapsed_time if elapsed_time > 0 else 0
        with PRINT_LOCK:
            sys.stdout.write(f"\rKeys Checked: {keys_checked.value:,} | Speed: {keys_per_second:,.2f} keys/sec | Elapsed Time: {format_time(elapsed_time)}")
            sys.stdout.flush()

def search_key(args):
    keys_checked, worker_id = args
    local_count = 0

    while not found.value:
        sub_range_min = random.randint(PRIVATE_KEY_MIN, PRIVATE_KEY_MAX - SUB_RANGE_SIZE + 1)
        sub_range_max = min(sub_range_min + SUB_RANGE_SIZE - 1, PRIVATE_KEY_MAX)

        short_min = hex(sub_range_min)[2:].upper().zfill(18)[:8]
        short_max = hex(sub_range_max)[2:].upper().zfill(18)[:8]
        with PRINT_LOCK:
            print(f"\n{Fore.YELLOW}Worker {worker_id:<2} searching sub-range: {short_min} - {short_max} (2^20 keys){Style.RESET_ALL}")

        for private_key in range(sub_range_min, sub_range_max + 1):
            if found.value:
                break
            try:
                private_key_raw = private_key.to_bytes(32, 'big').hex()
                public_key = private_key_to_public_key(private_key)
                compressed_public_key = compress_public_key(public_key)
                btc_address = public_key_to_address(compressed_public_key)
                wif = private_key_to_wif(private_key)

                local_count += 1
                if local_count >= 1000:
                    with PRINT_LOCK:
                        keys_checked.value += local_count
                    local_count = 0

                if btc_address == TARGET_BTC_ADDRESS:
                    with found.get_lock():
                        if not found.value:
                            found.value = True
                            with PRINT_LOCK:
                                keys_checked.value += local_count
                                print("\n===== MATCH FOUND! =====")
                                print(f"Worker: {worker_id}")
                                print(f"Keys Checked: {keys_checked.value:,}")
                                print(f"Private Key (Hex): {hex(private_key)}")
                                print(f"Private Key (Raw): {private_key_raw}")
                                print(f"Private Key (WIF): {wif}")
                                print(f"Compressed Public Key: {compressed_public_key.hex()}")
                                print(f"Bitcoin Address: {btc_address}")

                                balance = check_btc_balance(btc_address)
                                if balance is not None:
                                    print(f"Balance: {balance:.8f} BTC")

                                with open("found_key_71.txt", "w") as f:
                                    f.write(f"Worker: {worker_id}\n")
                                    f.write(f"Keys Checked: {keys_checked.value:,}\n")
                                    f.write(f"Private Key (Hex): {hex(private_key)}\n")
                                    f.write(f"Private Key (Raw): {private_key_raw}\n")
                                    f.write(f"Private Key (WIF): {wif}\n")
                                    f.write(f"Compressed Public Key: {compressed_public_key.hex()}\n")
                                    f.write(f"Bitcoin Address: {btc_address}\n")
                                    if balance is not None:
                                        f.write(f"Balance: {balance:.8f} BTC\n")
                            break
            except Exception as e:
                with PRINT_LOCK:
                    print(f"\nError processing key {hex(private_key)}: {e}")
                continue

        if local_count > 0:
            with PRINT_LOCK:
                keys_checked.value += local_count
            local_count = 0

if __name__ == "__main__":
    manager = Manager()
    keys_checked = manager.Value('i', 0)

    physical_cores, logical_cores = get_cpu_info()
    recommended_workers = max(1, physical_cores - 1) if physical_cores > 2 else physical_cores

    print(f"{Fore.CYAN}\nCPU Information:{Style.RESET_ALL}")
    print(f"Physical cores: {physical_cores}")
    if physical_cores != logical_cores:
        print(f"Logical cores (with hyperthreading): {logical_cores}")

    try:
        num_workers = int(input(
            f"\nEnter number of workers (1-{physical_cores}, recommended {recommended_workers}): ")
            or recommended_workers)
        if num_workers < 1 or num_workers > physical_cores:
            raise ValueError
        if num_workers >= physical_cores:
            print("\nWarning: Using all physical cores may make your system unresponsive!")
            print("Continuing in 3 seconds... (Ctrl+C to abort)")
            time.sleep(3)
    except ValueError:
        print(f"\nInvalid input. Please enter a number between 1 and {physical_cores}.")
        sys.exit(1)

    print(f"{Fore.RED}\nTarget Puzzle 71: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU{Style.RESET_ALL}")
    print(f"Total Range: {hex(PRIVATE_KEY_MIN)[2:].upper()} to {hex(PRIVATE_KEY_MAX)[2:].upper()} (2^62 keys)")
    print(f"Sub-Range Size: 2^20 keys\n")

    start_time = time.time()
    print_process = Process(target=print_keys_checked, args=(keys_checked, start_time))
    print_process.start()

    with Pool(num_workers) as p:
        p.map(search_key, [(keys_checked, i) for i in range(num_workers)])

    print_process.terminate()
    print_process.join()
