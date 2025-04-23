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

from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1

init()

# Configuration
TARGET_BTC_ADDRESS = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"
PRIVATE_KEY_MIN = 0x4000000000000000000000000000000000  # 2^130
PRIVATE_KEY_MAX = 0x7fffffffffffffffffffffffffffffffff  # 2^131 - 1
DP_BITS = 20  # Distinguished points mask (last 20 bits)
BATCH_SIZE = 10000  # Steps before updating shared counter
JUMP_COUNT = 32     # Number of jumps in jump table

# secp256k1 constants
CURVE = ecdsa.SECP256k1
G = CURVE.generator
N = CURVE.order

# Compressed public key
COMPRESSED_PUBLIC_KEY = bytes.fromhex("02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16")

# Shared state
found = Value('b', False)
PRINT_LOCK = Lock()

def compress_public_key(public_key):
    """Compress public key by dropping y-coordinate and using prefix"""
    x = public_key[1:33]
    y = public_key[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def decompress_pubkey(compressed):
    """Decompress a compressed secp256k1 public key to (x, y) Point"""
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], 'big')
    curve = SECP256k1.curve
    p = curve.p()
    a = curve.a()
    b = curve.b()

    # y^2 = x^3 + ax + b mod p
    alpha = (pow(x, 3, p) + a * x + b) % p
    beta = pow(alpha, (p + 1) // 4, p)

    y = beta if (beta % 2 == 0) == (prefix == 0x02) else p - beta
    return Point(curve, x, y)

def check_btc_balance(address):
    """Check Bitcoin address balance using blockchain.info API"""
    try:
        response = requests.get(f"https://blockchain.info/q/addressbalance/{address}", timeout=10)
        response.raise_for_status()
        satoshis = int(response.text)
        return satoshis / 100000000
    except Exception as e:
        with PRINT_LOCK:
            print(f"\nError checking balance: {e}")
        return None

def get_cpu_info():
    """Get CPU core information for optimal worker count"""
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return (physical, logical) if physical else (logical, logical)
    except:
        logical = cpu_count()
        return (logical, logical)

def private_key_to_public_key(private_key):
    """Convert private key to uncompressed public key"""
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address(compressed_public_key):
    """Convert compressed public key to Bitcoin address"""
    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    address_bytes = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    return base58.b58encode(address_bytes + checksum).decode('utf-8')

def private_key_to_wif(private_key):
    """Convert private key to Wallet Import Format"""
    extended_key = b'\x80' + private_key.to_bytes(32, 'big') + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode('utf-8')

def format_time(seconds):
    """Format seconds to HH:MM:SS"""
    hrs, rem = divmod(int(seconds), 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"

def print_keys_checked(keys_checked, start_time):
    """Display progress information"""
    while not found.value:
        time.sleep(1)
        elapsed_time = time.time() - start_time
        keys_per_second = keys_checked.value / elapsed_time if elapsed_time > 0 else 0
        with PRINT_LOCK:
            sys.stdout.write(f"\rSteps Taken: {keys_checked.value:,} | Speed: {keys_per_second:,.2f} steps/sec | Elapsed Time: {format_time(elapsed_time)}")
            sys.stdout.flush()

def initialize_kangaroos(worker_id, Q):
    """Initialize kangaroos with optimized starting positions"""
    range_size = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN
    random.seed(worker_id + int(time.time()))
    
    # Tame kangaroo starts in [a, b]
    tame_start = PRIVATE_KEY_MIN + random.randint(0, range_size)
    tame_point = tame_start * G
    tame_distance = tame_start
    
    # Wild kangaroo starts in [0, range_size] offset from Q
    wild_start = random.randint(0, range_size)
    wild_point = Q + (PRIVATE_KEY_MIN + wild_start) * G
    wild_distance = wild_start
    
    return tame_point, tame_distance, wild_point, wild_distance

def verify_and_save(private_key, keys_checked, worker_id, local_count):
    """Verify found key and save results"""
    private_key_raw = private_key.to_bytes(32, 'big').hex()
    public_key = private_key_to_public_key(private_key)
    compressed_public_key = compress_public_key(public_key)
    btc_address = public_key_to_address(compressed_public_key)
    
    if btc_address == TARGET_BTC_ADDRESS:
        with found.get_lock():
            if not found.value:
                found.value = True
                wif = private_key_to_wif(private_key)
                with PRINT_LOCK:
                    keys_checked.value += local_count
                    print("\n===== MATCH FOUND! =====")
                    print(f"Worker: {worker_id}")
                    print(f"Steps Taken: {keys_checked.value:,}")
                    print(f"Private Key (Hex): {hex(private_key)}")
                    print(f"Private Key (Raw): {private_key_raw}")
                    print(f"Private Key (WIF): {wif}")
                    print(f"Compressed Public Key: {compressed_public_key.hex()}")
                    print(f"Bitcoin Address: {btc_address}")
                    balance = check_btc_balance(btc_address)
                    if balance is not None:
                        print(f"Balance: {balance:.8f} BTC")
                    
                    with open("found_key_135.txt", "w") as f:
                        f.write(f"Worker: {worker_id}\n")
                        f.write(f"Steps Taken: {keys_checked.value:,}\n")
                        f.write(f"Private Key (Hex): {hex(private_key)}\n")
                        f.write(f"Private Key (Raw): {private_key_raw}\n")
                        f.write(f"Private Key (WIF): {wif}\n")
                        f.write(f"Compressed Public Key: {compressed_public_key.hex()}\n")
                        f.write(f"Bitcoin Address: {btc_address}\n")
                        if balance is not None:
                            f.write(f"Balance: {balance:.8f} BTC\n")

def self_check_and_store(point, distance, is_tame, distinguished_points, keys_checked, worker_id, Q, local_count):
    """Handle distinguished point checking and collision detection"""
    point_x = point.x()
    
    if point_x in distinguished_points:
        other_distance, other_is_tame = distinguished_points[point_x]
        
        if is_tame != other_is_tame:  # Only check tame-wild collisions
            if is_tame:
                k = (distance - other_distance) % N
            else:
                k = (other_distance - distance) % N
            
            if PRIVATE_KEY_MIN <= k <= PRIVATE_KEY_MAX:
                verify_and_save(k, keys_checked, worker_id, local_count)
    else:
        distinguished_points[point_x] = (distance, is_tame)

def search_key(args):
    """Pollard's Kangaroo algorithm implementation with optimizations"""
    keys_checked, worker_id, distinguished_points = args
    local_count = 0
    last_report = time.time()
    
    # Derive Q from compressed public key
    Q = decompress_pubkey(COMPRESSED_PUBLIC_KEY)
    
    # Initialize kangaroos
    tame_point, tame_distance, wild_point, wild_distance = initialize_kangaroos(worker_id, Q)
    
    # Precompute jump table
    jump_exponents = [1 << (i//2 + i%2) for i in range(JUMP_COUNT)]
    jumps = [exp * G for exp in jump_exponents]
    DP_MASK = (1 << DP_BITS) - 1
    
    while not found.value:
        try:
            # Tame kangaroo jump
            h_tame = (tame_point.x() & 0xFFFF) % JUMP_COUNT  # Simplified hash
            tame_point += jumps[h_tame]
            tame_distance += jump_exponents[h_tame]
            
            # Wild kangaroo jump
            h_wild = (wild_point.x() & 0xFFFF) % JUMP_COUNT  # Simplified hash
            wild_point += jumps[h_wild]
            wild_distance += jump_exponents[h_wild]
            
            local_count += 2
            
            # Batch update shared counter
            if local_count >= BATCH_SIZE:
                with PRINT_LOCK:
                    keys_checked.value += local_count
                local_count = 0
            
            # Check for distinguished points
            if (tame_point.x() & DP_MASK) == 0:
                self_check_and_store(tame_point, tame_distance, True, distinguished_points, 
                                  keys_checked, worker_id, Q, local_count)
            
            if (wild_point.x() & DP_MASK) == 0:
                self_check_and_store(wild_point, wild_distance, False, distinguished_points,
                                   keys_checked, worker_id, Q, local_count)
            
            # Periodic progress report
            if time.time() - last_report > 60 + worker_id * 5:
                with PRINT_LOCK:
                    print(f"{Fore.LIGHTWHITE_EX}\nWorker {worker_id}: {keys_checked.value:,} steps, {len(distinguished_points)} DPs{Style.RESET_ALL}")
                last_report = time.time()
                
        except Exception as e:
            with PRINT_LOCK:
                print(f"\nWorker {worker_id} error: {str(e)[:100]}")
            continue

if __name__ == "__main__":
    manager = Manager()
    keys_checked = manager.Value('i', 0)
    distinguished_points = manager.dict()

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

    print(f"\nUsing Pollard's Kangaroo for ECDLP on secp256k1")
    print(f"{Fore.RED}Target Puzzle 135: {TARGET_BTC_ADDRESS}{Style.RESET_ALL}")
    print(f"Range: {hex(PRIVATE_KEY_MIN)[2:].upper()} to {hex(PRIVATE_KEY_MAX)[2:].upper()} (2^130 keys)\n")

    # Sanity check: Does the compressed pubkey produce the expected BTC address?
    derived_address = public_key_to_address(COMPRESSED_PUBLIC_KEY)
    #print(f"\nDerived address: {derived_address}")
    #print(f"Target address : {TARGET_BTC_ADDRESS}")

    if derived_address != TARGET_BTC_ADDRESS:
        print(Fore.RED + "\n❌ ERROR: Compressed public key does NOT match the target address!" + Style.RESET_ALL)
        print("Please double-check your public key and address input.\n")
        sys.exit(1)
    else:
        print(Fore.YELLOW + "\nPublic key matches the target address. Starting search...\n" + Style.RESET_ALL)

    start_time = time.time()
    print_process = Process(target=print_keys_checked, args=(keys_checked, start_time))
    print_process.start()

    with Pool(num_workers) as p:
        p.map(search_key, [(keys_checked, i, distinguished_points) for i in range(num_workers)])

    print_process.terminate()
    print_process.join()