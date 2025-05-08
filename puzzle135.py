import os, random, requests, hashlib, ecdsa, base58, time, sys, psutil
from multiprocessing import Value, Lock, Process, cpu_count
from colorama import Fore, Style, init
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1

init(autoreset=True)

# === Configuration ===
TARGET_BTC_ADDRESS = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"
PRIVATE_KEY_MIN = 0x4000000000000000000000000000000000
PRIVATE_KEY_MAX = 0x7fffffffffffffffffffffffffffffffff
DP_BITS = 20
BATCH_SIZE = 10000
JUMP_COUNT = 32

CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order
COMPRESSED_PUBLIC_KEY = bytes.fromhex("02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16")

found = Value('b', False)
PRINT_LOCK = Lock()

# === Utility Functions ===

def compress_public_key(pubkey):
    x, y = pubkey[1:33], pubkey[33:65]
    return (b'\x02' if y[-1] % 2 == 0 else b'\x03') + x

def decompress_pubkey(compressed):
    prefix, x = compressed[0], int.from_bytes(compressed[1:], 'big')
    curve = SECP256k1.curve
    p, a, b = curve.p(), curve.a(), curve.b()
    alpha = (pow(x, 3, p) + a * x + b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == (prefix == 0x02) else p - beta
    return Point(curve, x, y)

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    return b'\x04' + sk.verifying_key.to_string()

def public_key_to_address(compressed_pubkey):
    sha = hashlib.sha256(compressed_pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    prefixed = b'\x00' + ripe
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    return base58.b58encode(prefixed + checksum).decode()

def private_key_to_wif(private_key):
    extended = b'\x80' + private_key.to_bytes(32, 'big') + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode()

def format_time(seconds):
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02}:{m:02}:{s:02}"

# === Output Reporter ===

def print_keys_checked(keys_checked, start_time):
    while not found.value:
        time.sleep(1)
        elapsed = time.time() - start_time
        kps = keys_checked.value / elapsed if elapsed > 0 else 0
        with PRINT_LOCK:
            sys.stdout.write(f"\r{Fore.LIGHTWHITE_EX}Steps: {keys_checked.value:,} | Speed: {kps:,.2f} keys/sec | Time: {format_time(elapsed)}{Style.RESET_ALL}")
            sys.stdout.flush()

# === Collision Verifier ===

def verify_key(private_key, keys_checked, worker_id, local_count):
    pubkey = private_key_to_public_key(private_key)
    compressed = compress_public_key(pubkey)
    addr = public_key_to_address(compressed)
    if addr == TARGET_BTC_ADDRESS:
        with found.get_lock():
            if not found.value:
                found.value = True
                wif = private_key_to_wif(private_key)
                with PRINT_LOCK:
                    keys_checked.value += local_count
                    print(f"\n\n{Fore.GREEN}MATCH FOUND by Worker {worker_id}")
                    print(f"{'-'*50}")
                    print(f"Private Key (hex): {hex(private_key)}")
                    print(f"Private Key (WIF): {wif}")
                    print(f"Address         : {addr}")
                    print(f"Saved to        : found_key_135.txt{Style.RESET_ALL}")
                with open("found_key_135.txt", "w") as f:
                    f.write(f"Private Key (hex): {hex(private_key)}\n")
                    f.write(f"WIF: {wif}\n")
                    f.write(f"Address: {addr}\n")

def self_check(point, distance, is_tame, dpoints, keys_checked, worker_id, Q, local_count):
    x = point.x()
    if x in dpoints:
        odist, otype = dpoints[x]
        if is_tame != otype:
            k = (distance - odist) % N if is_tame else (odist - distance) % N
            if PRIVATE_KEY_MIN <= k <= PRIVATE_KEY_MAX:
                verify_key(k, keys_checked, worker_id, local_count)
    else:
        dpoints[x] = (distance, is_tame)

# === Worker Thread ===

def search_key(args):
    keys_checked, worker_id = args
    local_count = 0
    last_report = time.time()
    Q = decompress_pubkey(COMPRESSED_PUBLIC_KEY)
    range_size = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN
    random.seed(worker_id + int(time.time()))

    G_base = PRIVATE_KEY_MIN * G
    wild_start = random.randint(0, range_size)
    tame_start = PRIVATE_KEY_MIN + random.randint(0, range_size)
    tame, tame_dist = tame_start * G, tame_start
    wild, wild_dist = Q + G_base + wild_start * G, wild_start

    exps = [2**i for i in range(JUMP_COUNT)]
    jumps = [e * G for e in exps]
    DP_MASK = (1 << DP_BITS) - 1
    dpoints = {}

    while not found.value:
        for point, dist, is_tame in [(tame, tame_dist, True), (wild, wild_dist, False)]:
            h = point.x() % JUMP_COUNT
            point += jumps[h]
            dist += exps[h]

            if is_tame:
                tame, tame_dist = point, dist
            else:
                wild, wild_dist = point, dist

            local_count += 1
            if point.x() & DP_MASK == 0:
                self_check(point, dist, is_tame, dpoints, keys_checked, worker_id, Q, local_count)

        if local_count >= BATCH_SIZE:
            with PRINT_LOCK:
                keys_checked.value += local_count
            local_count = 0

        if time.time() - last_report > 60 + worker_id * 5:
            with PRINT_LOCK:
                print(f"\n{Fore.LIGHTCYAN_EX}Worker {worker_id}: {keys_checked.value:,} steps, {len(dpoints)} DPs{Style.RESET_ALL}")
            last_report = time.time()

def get_cpu_info():
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return (physical or logical, logical)
    except:
        return (cpu_count(), cpu_count())

# === Entry Point ===

if __name__ == "__main__":
    physical, logical = get_cpu_info()
    recommended = max(1, physical - 1)

    print(f"\n{Fore.CYAN}=== Pollard's Kangaroo for Bitcoin Puzzle #135 ==={Style.RESET_ALL}")
    print(f"{Fore.BLUE}Target Address  : {TARGET_BTC_ADDRESS}")
    print(f"Public Key Hash : {COMPRESSED_PUBLIC_KEY.hex()[:16]}...{Style.RESET_ALL}")
    print(f"Range           : {hex(PRIVATE_KEY_MIN)} to {hex(PRIVATE_KEY_MAX)} ({(PRIVATE_KEY_MAX - PRIVATE_KEY_MIN):,} keys)\n")

    try:
        num_workers = int(input(f"{Fore.CYAN}Enter number of workers (1-{physical}, default {recommended}): {Style.RESET_ALL}") or recommended)
        if not (1 <= num_workers <= physical):
            raise ValueError
        if num_workers == physical:
            print(f"{Fore.YELLOW}Using all cores may impact system responsiveness. Starting in 3s...{Style.RESET_ALL}")
            time.sleep(3)
    except ValueError:
        print(f"{Fore.RED}Invalid input. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    derived = public_key_to_address(COMPRESSED_PUBLIC_KEY)
    if derived != TARGET_BTC_ADDRESS:
        print(f"\n{Fore.RED}Compressed public key does NOT match the target address!{Style.RESET_ALL}\n")
        sys.exit(1)
    else:
        print(f"{Fore.YELLOW}Public key matches target address. Beginning search...{Style.RESET_ALL}\n")

    start_time = time.time()
    keys_checked = Value('i', 0)
    printer = Process(target=print_keys_checked, args=(keys_checked, start_time))
    printer.start()

    workers = []
    for i in range(num_workers):
        p = Process(target=search_key, args=((keys_checked, i),))
        p.start()
        workers.append(p)

    for p in workers:
        p.join()

    printer.terminate()
    printer.join()
