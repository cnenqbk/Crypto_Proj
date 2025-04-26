import os
import random
import requests
import hashlib
import ecdsa
import base58
import time
import sys
import psutil
from multiprocessing import Pool, Value, cpu_count, Manager, Lock, Process
from colorama import Fore, Style, init
init()  # Required for Windows support

# Load BTC addresses from file
def load_btc_addresses(filename="lists.txt"):
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        sys.exit(1)
    with open(filename, "r") as f:
        return set(line.strip() for line in f if line.strip())

TARGET_BTC_ADDRESSES = load_btc_addresses()

PRIVATE_KEY_MIN = 0x0000000000000000000000000000000000000000000000000000000000000001
PRIVATE_KEY_MAX = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140

found = Value('b', False)  # Flag to indicate when a match is found
lock = Lock()  # Lock for synchronized printing
BATCH_SIZE = 100000 if cpu_count() <= 2 else 10000  # Generate multiple keys at once for efficiency
SUB_RANGE_SIZE = 2**64  # Focus on smaller chunks to explore the range

# Functions
def compress_public_key(public_key):
    x = public_key[1:33]
    y = public_key[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def check_btc_balance(address):
    """Check BTC balance using blockchain.com API"""
    import requests
    try:
        response = requests.get(f"https://blockchain.info/q/addressbalance/{address}")
        response.raise_for_status()
        satoshis = int(response.text)
        return satoshis / 100000000  # Convert satoshis to BTC
    except Exception as e:
        print(f"\nError checking balance: {e}")
        return None

def get_cpu_info():
    """Return tuple of (physical_cores, logical_cores)"""
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
    public_key = b'\x04' + vk.to_string()
    return public_key

def public_key_to_address(compressed_public_key):
    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    address_bytes = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    binary_address = address_bytes + checksum
    return base58.b58encode(binary_address).decode('utf-8')

def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key.to_bytes(32, 'big') + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    return wif

def format_time(seconds):
    hrs = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hrs:02}:{mins:02}:{secs:02}"

def print_keys_checked(keys_checked, start_time):
    while not found.value:
        time.sleep(1)
        elapsed_time = time.time() - start_time
        keys_per_second = keys_checked.value / elapsed_time if elapsed_time > 0 else 0
        with lock:
            sys.stdout.write(f"\rKeys Checked: {keys_checked.value} | Speed: {keys_per_second:.2f} keys/sec | Elapsed Time: {format_time(elapsed_time)}")
            sys.stdout.flush()

def search_key(keys_checked, num_workers):
    local_count = 0

    # Pick a random sub-range to focus on
    sub_range_min = random.randint(PRIVATE_KEY_MIN, PRIVATE_KEY_MAX - SUB_RANGE_SIZE)
    sub_range_max = min(sub_range_min + SUB_RANGE_SIZE, PRIVATE_KEY_MAX)
    with lock:
         
        print(f"{Fore.YELLOW}Random Sub-Range: {sub_range_min:X}-{sub_range_max:X} (Size: {sub_range_max - sub_range_min + 1} keys){Style.RESET_ALL}\n")

    while not found.value:
        keys = [random.randint(sub_range_min, sub_range_max) for _ in range(BATCH_SIZE)]
        for private_key in keys:
            private_key_raw = private_key.to_bytes(32, 'big').hex()
            public_key = private_key_to_public_key(private_key)
            compressed_public_key = compress_public_key(public_key)
            btc_address = public_key_to_address(compressed_public_key)
            wif = private_key_to_wif(private_key)

            if btc_address in TARGET_BTC_ADDRESSES:
                with found.get_lock():
                    if not found.value:
                        found.value = True
                        print("\n===== MATCH FOUND! =====")
                        print(f"Keys Checked: {keys_checked.value + local_count}")
                        print(f"Private Key (Hex): {hex(private_key)}")
                        print(f"Private Key (Raw): {private_key_raw}")
                        print(f"Private Key (WIF): {wif}")
                        print(f"Compressed Public Key: {compressed_public_key.hex()}")
                        print(f"Bitcoin Address: {btc_address}")

                        # New balance check functionality
                        try:
                            balance = check_btc_balance(btc_address)
                            if balance is not None:
                                print(f"Balance: {balance:.8f} BTC")
                        except Exception as e:
                            print(f"Could not check balance: {str(e)}")

                        with open("found_key.txt", "w") as f:
                            f.write(f"Private Key (Hex): {hex(private_key)}\n")
                            f.write(f"Private Key (Raw): {private_key_raw}\n")
                            f.write(f"Private Key (WIF): {wif}\n")
                            f.write(f"Compressed Public Key: {compressed_public_key.hex()}\n")
                            f.write(f"Bitcoin Address: {btc_address}\n")
                            try:
                                if balance is not None:
                                    f.write(f"Balance: {balance:.8f} BTC\n")
                            except NameError:
                                pass
                        break
            local_count += 1

        # Increment keys checked safely only once per batch
        with lock:
            keys_checked.value += local_count
        local_count = 0

if __name__ == "__main__":
    manager = Manager()
    keys_checked = manager.Value('i', 0)

     # Get CPU information using your existing function
    physical_cores, logical_cores = get_cpu_info()
    
    # Calculate recommended workers (leave 1 core free for systems with >2 cores)
    recommended_workers = max(1, physical_cores - 1) if physical_cores > 2 else physical_cores
    
    print(f"{Fore.CYAN}\nCPU Information:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Physical cores: {physical_cores}{Style.RESET_ALL}")
    if physical_cores != logical_cores:
        print(f"{Fore.CYAN}Logical cores (with hyperthreading): {logical_cores}{Style.RESET_ALL}")
    
    try:
        num_workers = int(input(
            f"\nEnter number of workers (1-{physical_cores}, recommended {recommended_workers}): ")
            or recommended_workers)
        
        if num_workers < 1 or num_workers > logical_cores:
            raise ValueError
            
        if num_workers >= physical_cores:
            print("\nWarning: Using all physical cores may make your system unresponsive!")
            print("The script will continue in 3 seconds... (Ctrl+C to abort)")
            time.sleep(3)
    
    except ValueError:
        print(f"\nInvalid input. Please enter a number between 1 and {physical_cores}.")
        sys.exit(1)
    
    start_time = time.time()

        # Print full range and sub-range details
    full_range_size = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    print(f"\nCurrent Full Range: {PRIVATE_KEY_MIN:X} to {PRIVATE_KEY_MAX:X} (~2^256 keys)")
    print(f"Sub-Range Size: 2^64 keys, 18.4 quintillion keys\n")

    print_process = Process(target=print_keys_checked, args=(keys_checked, start_time))
    print_process.start()

    with Pool(num_workers) as p:
        p.starmap(search_key, [(keys_checked, num_workers) for _ in range(num_workers)])

    print_process.terminate()  # Stop the print process once done
    print_process.join()
