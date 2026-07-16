import requests
import hashlib
import ecdsa
import base58
import time
import sys
import psutil
import shutil
import random
import os
import queue
import signal
from multiprocessing import Pool, Value, Lock, Process, cpu_count, Manager
from colorama import Fore, Style, init

init()

try:
    from coincurve import PrivateKey as CoincurvePrivateKey
    HAS_COINCURVE = True
except ImportError:
    CoincurvePrivateKey = None
    HAS_COINCURVE = False

# Target Bitcoin address
TARGET_BTC_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# IMPROVEMENT 1: Pre-calculate the target 20-byte Hash160 to avoid Base58 encoding in the loop
TARGET_HASH160 = base58.b58decode_check(TARGET_BTC_ADDRESS)[1:]

# Private key range
PRIVATE_KEY_MIN = 0x400000000000000000
PRIVATE_KEY_MAX = 0x7FFFFFFFFFFFFFFFFF

# Config
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
found = None
keys_checked = None
chunk_counter = None
PRINT_LOCK = None

# IMPROVEMENT 2: Fixed the missing ** exponentiation operators
SUB_RANGE_SIZE = 2**20  # 1,048,576 keys
RANDOM_SUB_RANGE_SIZE = 2**18  # 262,144 keys

RANDOM_HISTORY_FILE = r"E:\puzzle71_random_done.txt"
FOUND_KEY_FILE = os.path.join(SCRIPT_DIR, "found_key_71.txt")
SHOW_CHUNKS = False
random_chunk_queue = None
random_history_lock = None

def ignore_keyboard_interrupt():
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass

def init_worker(shared_found, shared_keys_checked, shared_chunk_counter, shared_print_lock):
    global found, keys_checked, chunk_counter, PRINT_LOCK
    ignore_keyboard_interrupt()
    found = shared_found
    keys_checked = shared_keys_checked
    chunk_counter = shared_chunk_counter
    PRINT_LOCK = shared_print_lock
    set_low_priority()

def init_random_worker(
    shared_found,
    shared_keys_checked,
    shared_random_chunk_queue,
    shared_print_lock,
    shared_random_history_lock,
):
    global found, keys_checked, random_chunk_queue, PRINT_LOCK, random_history_lock
    ignore_keyboard_interrupt()
    found = shared_found
    keys_checked = shared_keys_checked
    random_chunk_queue = shared_random_chunk_queue
    PRINT_LOCK = shared_print_lock
    random_history_lock = shared_random_history_lock
    set_low_priority()

# --- Utility functions ---

def compress_public_key(public_key):
    x = public_key[1:33]
    y = public_key[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def check_btc_balance(address):
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
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return (physical, logical) if physical else (logical, logical)
    except Exception:
        logical = cpu_count()
        return (logical, logical)

def set_low_priority():
    try:
        process = psutil.Process(os.getpid())
        if sys.platform.startswith("win"):
            process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            process.nice(10)
        return True
    except Exception:
        return False

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def private_key_to_compressed_public_key(private_key):
    private_key_bytes = private_key.to_bytes(32, 'big')
    if HAS_COINCURVE:
        return CoincurvePrivateKey(private_key_bytes).public_key.format(compressed=True)
    return compress_public_key(private_key_to_public_key(private_key))

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

def format_eta(seconds):
    if seconds <= 0:
        return "00:00:00"
    years = seconds / 31_536_000
    if years >= 100:
        return ">100y"
    if years >= 1:
        return f"{years:.1f}y"
    days = seconds / 86_400
    if days >= 1:
        return f"{days:.1f}d"
    return format_time(seconds)

def format_rate(rate):
    if rate >= 1_000_000_000:
        return f"{rate / 1_000_000_000:.2f}B"
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f}M"
    if rate >= 1_000:
        return f"{rate / 1_000:.2f}K"
    return f"{rate:.2f}"

def progress_bar(percent, width=24):
    filled = int(width * percent / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"

def parse_positive_int(value, label):
    try:
        number = int(value.strip())
    except ValueError:
        raise ValueError(f"{label} must be a whole number.")
    if number < 1:
        raise ValueError(f"{label} must be 1 or greater.")
    return number

def percent_window(range_start, range_end):
    total = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    start_percent = ((range_start - PRIVATE_KEY_MIN) / total) * 100
    end_percent = ((range_end - PRIVATE_KEY_MIN + 1) / total) * 100
    return start_percent, end_percent

def format_percent(value):
    if value == 0:
        return "0%"
    if value < 0.000001:
        return f"{value:.12f}%"
    if value < 0.01:
        return f"{value:.8f}%"
    return f"{value:.6f}%"

def print_range_summary(range_start, range_end, label="Selected range"):
    full_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    selected_keys = range_end - range_start + 1
    selected_percent = (selected_keys / full_keys) * 100
    start_percent, end_percent = percent_window(range_start, range_end)
    print(f"\n{Fore.LIGHTWHITE_EX}Range Size{Style.RESET_ALL}")
    print(f"Full range:     {hex(PRIVATE_KEY_MIN)[2:].upper()} to {hex(PRIVATE_KEY_MAX)[2:].upper()}")
    print(f"Full keys:      {full_keys:,}")
    print(f"{label}: {hex(range_start)[2:].upper()} to {hex(range_end)[2:].upper()}")
    print(f"Selected keys:  {selected_keys:,}")
    print(f"Selected size:  {format_percent(selected_percent)} of full range")
    print(f"Percent window: {format_percent(start_percent)} to {format_percent(end_percent)}")

def load_random_history():
    completed = set()
    if not os.path.exists(RANDOM_HISTORY_FILE):
        return completed
    with open(RANDOM_HISTORY_FILE, "r") as f:
        for line in f:
            value = line.strip()
            if not value:
                continue
            try:
                completed.add(int(value))
            except ValueError:
                continue
    return completed

def save_completed_random_chunk(chunk_index):
    with random_history_lock:
        with open(RANDOM_HISTORY_FILE, "a") as f:
            f.write(f"{chunk_index}\n")

def total_random_chunks():
    total_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    return (total_keys + RANDOM_SUB_RANGE_SIZE - 1) // RANDOM_SUB_RANGE_SIZE

def random_chunk_bounds(chunk_index):
    start = PRIVATE_KEY_MIN + (chunk_index * RANDOM_SUB_RANGE_SIZE)
    end = min(start + RANDOM_SUB_RANGE_SIZE - 1, PRIVATE_KEY_MAX)
    return start, end

def random_chunks_key_count(chunks):
    total = 0
    for chunk_index in chunks:
        start, end = random_chunk_bounds(chunk_index)
        total += end - start + 1
    return total

def print_random_time_estimates(total_keys):
    print("Estimated time:")
    for rate in (10_000, 20_000, 45_000, 100_000):
        print(f"  at {format_rate(rate)}/s: {format_eta(total_keys / rate)}")

def build_random_session_chunks(chunk_count, completed_chunks):
    max_chunks = total_random_chunks()
    remaining_chunks = max_chunks - len(completed_chunks)
    if remaining_chunks <= 0:
        raise ValueError("Every random mini chunk is already marked complete.")
    chunk_count = min(chunk_count, remaining_chunks)
    selected = set()
    max_attempts = chunk_count * 20
    attempts = 0
    while len(selected) < chunk_count and attempts < max_attempts:
        chunk_index = random.randrange(max_chunks)
        attempts += 1
        if chunk_index in completed_chunks or chunk_index in selected:
            continue
        selected.add(chunk_index)
    if len(selected) < chunk_count:
        for chunk_index in range(max_chunks):
            if len(selected) >= chunk_count:
                break
            if chunk_index not in completed_chunks and chunk_index not in selected:
                selected.add(chunk_index)
    chunks = list(selected)
    random.shuffle(chunks)
    return chunks

def prompt_random_session():
    print(f"\n{Fore.LIGHTWHITE_EX}Random Session{Style.RESET_ALL}")
    print("This searches random mini chunks and records completed chunks.")
    print(f"Mini chunk size: {RANDOM_SUB_RANGE_SIZE:,} keys each")
    queue_count = parse_positive_int(
        input("How many random mini chunks to search this run (default 100): ") or "100",
        "Random mini chunks",
    )
    completed_chunks = load_random_history()
    chunks = build_random_session_chunks(queue_count, completed_chunks)
    full_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    completed_keys = random_chunks_key_count(completed_chunks)
    completed_percent = (completed_keys / full_keys) * 100
    session_keys = random_chunks_key_count(chunks)
    session_percent = (session_keys / full_keys) * 100
    print(f"\nAlready completed mini chunks: {len(completed_chunks):,}")
    print(f"Already completed keys:        {completed_keys:,}")
    print(f"Already completed size:        {format_percent(completed_percent)} of full range")
    print(f"Prepared random mini chunks:  {len(chunks):,}")
    print(f"Prepared max keys:            {session_keys:,}")
    print(f"Prepared max size:            {format_percent(session_percent)} of full range")
    print("Run length:                   until prepared mini chunks finish")
    print_random_time_estimates(session_keys)
    print(f"History file:                 {RANDOM_HISTORY_FILE}")
    return chunks

def prompt_range_selection():
    full_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
    print(f"\n{Fore.LIGHTWHITE_EX}Range Selection{Style.RESET_ALL}")
    print(f"Full puzzle 71 range has {full_keys:,} keys.")
    print("1. Start        | first 1/3  | 33.333333%")
    print("2. Middle       | second 1/3 | 33.333333%")
    print("3. End          | last 1/3   | 33.333333%")
    print("4. Random time  | random mini chunks, no completed duplicates")
    choice = input("Choose: ").strip()
    third = full_keys // 3
    if choice == "1":
        return "deterministic", (PRIVATE_KEY_MIN, PRIVATE_KEY_MIN + third - 1), None
    if choice == "2":
        return "deterministic", (PRIVATE_KEY_MIN + third, PRIVATE_KEY_MIN + (2 * third) - 1), None
    if choice == "3":
        return "deterministic", (PRIVATE_KEY_MIN + (2 * third), PRIVATE_KEY_MAX), None
    if choice == "4":
        chunks = prompt_random_session()
        return "random", (PRIVATE_KEY_MIN, PRIVATE_KEY_MAX), chunks
    raise ValueError("Invalid range selection.")

def print_keys_checked(shared_found, shared_keys_checked, print_lock, start_time, total_keys):
    ignore_keyboard_interrupt()
    previous_width = 0
    try:
        while not shared_found.value:
            # IMPROVEMENT 3: Fixed broken variable names (tim e -> time, el apsed -> elapsed, etc.)
            time.sleep(1)
            elapsed_time = time.time() - start_time
            with shared_keys_checked.get_lock():
                current_keys = shared_keys_checked.value
            keys_per_second = current_keys / elapsed_time if elapsed_time > 0 else 0
            percent = min((current_keys / total_keys) * 100, 100) if total_keys else 0
            remaining_keys = max(total_keys - current_keys, 0)
            eta = format_eta(remaining_keys / keys_per_second) if keys_per_second > 0 else "--"
            
            status = (
                f"{progress_bar(percent, 12)} {percent:6.3f}% | "
                f"{current_keys:,} checked | "
                f"{format_rate(keys_per_second)}/s | "
                f"{format_time(elapsed_time)} | ETA {eta}"
            )
            terminal_width = max(shutil.get_terminal_size((100, 20)).columns - 1, 40)
            status = status[:terminal_width]
            clear_width = max(previous_width, len(status))
            previous_width = len(status)
            with print_lock:
                sys.stdout.write("\r" + status.ljust(clear_width))
                sys.stdout.flush()
    except KeyboardInterrupt:
        return

def search_key_chunked(args):
    """Search unique chunks assigned from a shared counter."""
    worker_id, RANGE_START, RANGE_END = args
    local_count = 0
    while not found.value:
        try:
            with chunk_counter.get_lock():
                chunk_index = chunk_counter.value
                chunk_counter.value += 1
            sub_range_min = RANGE_START + (chunk_index * SUB_RANGE_SIZE)
            if sub_range_min > RANGE_END:
                break
            sub_range_max = min(sub_range_min + SUB_RANGE_SIZE - 1, RANGE_END)
            
            if SHOW_CHUNKS:
                short_min = hex(sub_range_min)[2:].upper().zfill(18)[:8]
                short_max = hex(sub_range_max)[2:].upper().zfill(18)[:8]
                with PRINT_LOCK:
                    print(f"\n{Fore.YELLOW}Worker {worker_id:<2} searching sub-range: {short_min} - {short_max} ({sub_range_max - sub_range_min + 1:,} keys){Style.RESET_ALL}")
            
            for private_key in range(sub_range_min, sub_range_max + 1):
                if found.value:
                    break
                try:
                    compressed_public_key = private_key_to_compressed_public_key(private_key)
                    
                    # IMPROVEMENT 4: FAST PATH - Compare raw Hash160 bytes instead of Base58 string
                    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
                    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
                    
                    local_count += 1
                    # IMPROVEMENT 5: Increased batch size to 500,000 to reduce IPC lock contention
                    if local_count >= 500000:
                        with keys_checked.get_lock():
                            keys_checked.value += local_count
                        local_count = 0
                        
                    if ripemd160_bpk == TARGET_HASH160:
                        btc_address = public_key_to_address(compressed_public_key)
                        with found.get_lock():
                            if not found.value:
                                found.value = True
                                private_key_raw = private_key.to_bytes(32, 'big').hex()
                                wif = private_key_to_wif(private_key)
                                with keys_checked.get_lock():
                                    keys_checked.value += local_count
                                local_count = 0
                                balance = check_btc_balance(btc_address)
                                with PRINT_LOCK:
                                    print("\n" + "="*50)
                                    print(f"{Fore.GREEN}MATCH FOUND!{Style.RESET_ALL}")
                                    print("="*50)
                                    print(f"Worker: {worker_id}")
                                    print(f"Keys Checked: {keys_checked.value:,}")
                                    print(f"Private Key (Hex): {hex(private_key)}")
                                    print(f"Private Key (Raw): {private_key_raw}")
                                    print(f"Private Key (WIF): {wif}")
                                    print(f"Compressed Public Key: {compressed_public_key.hex()}")
                                    print(f"Bitcoin Address: {btc_address}")
                                    if balance is not None:
                                        print(f"Balance: {balance:.8f} BTC")
                                    with open(FOUND_KEY_FILE, "w") as f:
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
                with keys_checked.get_lock():
                    keys_checked.value += local_count
                local_count = 0
        except Exception as e:
            with PRINT_LOCK:
                print(f"\nWorker {worker_id} error in subrange selection: {e}")
            time.sleep(1)
            continue

def search_key_random(args):
    """Search random mini chunks from a prepared queue and record completed chunks."""
    worker_id = args[0]
    local_count = 0
    while not found.value:
        try:
            chunk_index = random_chunk_queue.get_nowait()
        except queue.Empty:
            break
        sub_range_min, sub_range_max = random_chunk_bounds(chunk_index)
        completed_chunk = True
        if SHOW_CHUNKS:
            with PRINT_LOCK:
                print(
                    f"\n{Fore.YELLOW}Worker {worker_id:<2} random mini chunk "
                    f"{chunk_index}: {hex(sub_range_min)[2:].upper()} - "
                    f"{hex(sub_range_max)[2:].upper()}{Style.RESET_ALL}"
                )
        for private_key in range(sub_range_min, sub_range_max + 1):
            if found.value:
                completed_chunk = False
                break
            try:
                compressed_public_key = private_key_to_compressed_public_key(private_key)
                
                # FAST PATH: Compare raw Hash160 bytes
                sha256_bpk = hashlib.sha256(compressed_public_key).digest()
                ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
                
                local_count += 1
                if local_count >= 500000:
                    with keys_checked.get_lock():
                        keys_checked.value += local_count
                    local_count = 0
                    
                if ripemd160_bpk == TARGET_HASH160:
                    btc_address = public_key_to_address(compressed_public_key)
                    completed_chunk = False
                    with found.get_lock():
                        if not found.value:
                            found.value = True
                            private_key_raw = private_key.to_bytes(32, 'big').hex()
                            wif = private_key_to_wif(private_key)
                            with keys_checked.get_lock():
                                keys_checked.value += local_count
                            local_count = 0
                            balance = check_btc_balance(btc_address)
                            with PRINT_LOCK:
                                print("\n" + "="*50)
                                print(f"{Fore.GREEN}MATCH FOUND!{Style.RESET_ALL}")
                                print("="*50)
                                print(f"Worker: {worker_id}")
                                print(f"Random Chunk: {chunk_index}")
                                print(f"Keys Checked: {keys_checked.value:,}")
                                print(f"Private Key (Hex): {hex(private_key)}")
                                print(f"Private Key (Raw): {private_key_raw}")
                                print(f"Private Key (WIF): {wif}")
                                print(f"Compressed Public Key: {compressed_public_key.hex()}")
                                print(f"Bitcoin Address: {btc_address}")
                                if balance is not None:
                                    print(f"Balance: {balance:.8f} BTC")
                                with open(FOUND_KEY_FILE, "w") as f:
                                    f.write(f"Worker: {worker_id}\n")
                                    f.write(f"Random Chunk: {chunk_index}\n")
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
            with keys_checked.get_lock():
                keys_checked.value += local_count
            local_count = 0
        if completed_chunk:
            save_completed_random_chunk(chunk_index)

def wait_for_pool(pool, search_method, tasks):
    result = pool.map_async(search_method, tasks)
    while not result.ready():
        time.sleep(0.2)
    result.get()

if __name__ == "__main__":
    found = Value('b', False)
    keys_checked = Value('Q', 0)
    chunk_counter = Value('Q', 0)
    PRINT_LOCK = Lock()
    
    print(f"{Fore.CYAN}\nPuzzle 71 Search{Style.RESET_ALL}")
    if set_low_priority():
        print("Process priority: below normal")
        
    physical_cores, logical_cores = get_cpu_info()
    recommended_workers = 1
    print(f"CPU: {physical_cores} physical cores", end="")
    if physical_cores != logical_cores:
        print(f", {logical_cores} logical cores")
    else:
        print()
        
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
        
    try:
        search_mode, selected_range, random_config = prompt_range_selection()
        RANGE_START, RANGE_END = selected_range
    except ValueError as e:
        print(f"\n{Fore.RED}{e}{Style.RESET_ALL}")
        sys.exit(1)
        
    if search_mode == "random":
        random_chunks = random_config
        total_keys = random_chunks_key_count(random_chunks)
        search_method = search_key_random
        method_name = "Random Mini Chunk Session"
    else:
        random_chunks = None
        total_keys = RANGE_END - RANGE_START + 1
        print_range_summary(RANGE_START, RANGE_END)
        search_method = search_key_chunked
        method_name = "Deterministic Chunk Search"
        
    print(f"\n{Fore.RED}Target: {TARGET_BTC_ADDRESS}{Style.RESET_ALL}")
    if search_mode == "random":
        print(f"Range: full Puzzle 71 range, random mini chunks only")
        print(f"Prepared Keys: {total_keys:,} | Workers: {num_workers} | Mini Chunk: 2^18")
    else:
        print(f"Range: {hex(RANGE_START)[2:].upper()} to {hex(RANGE_END)[2:].upper()}")
        print(f"Keys: {total_keys:,} | Workers: {num_workers} | Chunk: 2^20")
        
    print(f"Method: {method_name} | Backend: {'coincurve' if HAS_COINCURVE else 'ecdsa'}")
    if not HAS_COINCURVE:
        print(f"{Fore.YELLOW}Install coincurve for faster public-key generation: python -m pip install coincurve{Style.RESET_ALL}")
    print()
    
    start_time = time.time()
    print_process = Process(target=print_keys_checked, args=(found, keys_checked, PRINT_LOCK, start_time, total_keys))
    print_process.start()
    
    stopped_by_user = False
    try:
        if search_mode == "random":
            with Manager() as manager:
                chunk_queue = manager.Queue()
                for chunk_index in random_chunks:
                    chunk_queue.put(chunk_index)
                history_lock = manager.Lock()
                with Pool(
                    num_workers,
                    initializer=init_random_worker,
                    initargs=(
                        found,
                        keys_checked,
                        chunk_queue,
                        PRINT_LOCK,
                        history_lock,
                    ),
                ) as p:
                    wait_for_pool(p, search_method, [(i,) for i in range(num_workers)])
        else:
            with Pool(
                num_workers,
                initializer=init_worker,
                initargs=(found, keys_checked, chunk_counter, PRINT_LOCK),
            ) as p:
                wait_for_pool(p, search_method, [(i, RANGE_START, RANGE_END) for i in range(num_workers)])
    except KeyboardInterrupt:
        stopped_by_user = True
        with found.get_lock():
            found.value = True
        print(f"\n{Fore.YELLOW}Stopping search. Completed random chunks are already saved.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error in pool execution: {e}{Style.RESET_ALL}")
    finally:
        print_process.terminate()
        print_process.join()
        print()
        
    if stopped_by_user:
        print(f"\n{Fore.YELLOW}Search stopped by user.{Style.RESET_ALL}")
    elif not found.value:
        print(f"\n{Fore.RED}Search completed. Key not found.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}Search completed successfully!{Style.RESET_ALL}")
