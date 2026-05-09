import argparse
import base58
import hashlib
import math
import os
import random
import signal
import sys
import time
from multiprocessing import Lock, Process, Value, cpu_count

import ecdsa
import psutil
from colorama import Fore, Style, init
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

init(autoreset=True)

try:
    from coincurve import PrivateKey as CoincurvePrivateKey

    HAS_COINCURVE = True
except ImportError:
    CoincurvePrivateKey = None
    HAS_COINCURVE = False


# === Configuration ===
TARGET_BTC_ADDRESS = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"
COMPRESSED_PUBLIC_KEY = bytes.fromhex(
    "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
)

PRIVATE_KEY_MIN = 0x4000000000000000000000000000000000
PRIVATE_KEY_MAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order
RANGE_SIZE = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN

# Fewer DP bits means more memory and more collision checks. More DP bits means
# less overhead but longer waits between useful collision checks.
DEFAULT_DP_BITS = 20
DEFAULT_JUMP_COUNT = 64
DEFAULT_BATCH_SIZE = 50_000
FOUND_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "found_key_135.txt")


# === Utility Functions ===

def ignore_keyboard_interrupt():
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass


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


def get_cpu_info():
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return (physical or logical, logical or physical or cpu_count())
    except Exception:
        logical = cpu_count()
        return logical, logical


def decompress_pubkey(compressed):
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], "big")
    curve = SECP256k1.curve
    p, a, b = curve.p(), curve.a(), curve.b()
    alpha = (pow(x, 3, p) + a * x + b) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == 0) == (prefix == 0x02) else p - beta
    return Point(curve, x, y, N)


def compress_point(point):
    prefix = b"\x02" if point.y() % 2 == 0 else b"\x03"
    return prefix + int(point.x()).to_bytes(32, "big")


def private_key_to_compressed_public_key(private_key):
    private_key_bytes = private_key.to_bytes(32, "big")
    if HAS_COINCURVE:
        return CoincurvePrivateKey(private_key_bytes).public_key.format(compressed=True)

    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    raw_public_key = sk.verifying_key.to_string()
    y = raw_public_key[32:64]
    return (b"\x02" if y[-1] % 2 == 0 else b"\x03") + raw_public_key[:32]


def public_key_to_address(compressed_pubkey):
    sha = hashlib.sha256(compressed_pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    prefixed = b"\x00" + ripe
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    return base58.b58encode(prefixed + checksum).decode("utf-8")


def private_key_to_wif(private_key):
    extended = b"\x80" + private_key.to_bytes(32, "big") + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode("utf-8")


def format_time(seconds):
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02}:{m:02}:{s:02}"


def format_rate(rate):
    if rate >= 1_000_000_000:
        return f"{rate / 1_000_000_000:.2f}B"
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f}M"
    if rate >= 1_000:
        return f"{rate / 1_000:.2f}K"
    return f"{rate:.2f}"


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


def progress_bar(percent, width=18):
    filled = int(width * percent / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def estimate_sqrt_interval_steps():
    return math.isqrt(RANGE_SIZE)


def make_jump_table(jump_count):
    sqrt_range = estimate_sqrt_interval_steps()
    target_average = max(1, sqrt_range // 2)

    low = max(1, target_average // 2)
    high = max(low + 1, target_average + target_average // 2)
    seed_material = (
        COMPRESSED_PUBLIC_KEY
        + PRIVATE_KEY_MIN.to_bytes(32, "big")
        + PRIVATE_KEY_MAX.to_bytes(32, "big")
        + jump_count.to_bytes(2, "big")
    )
    rng = random.Random(int.from_bytes(hashlib.sha256(seed_material).digest(), "big"))

    exps = {target_average}
    while len(exps) < jump_count:
        exps.add(rng.randrange(low, high + 1))

    exps = sorted(exps)
    average = sum(exps) // len(exps)
    jumps = [step * G for step in exps]
    return exps, jumps, average


def point_key(point):
    return point.x(), point.y() & 1


def derive_candidate(this_distance, this_type, other_distance, other_type):
    if this_type == other_type:
        return None

    if this_type == "tame":
        tame_distance = this_distance
        wild_distance = other_distance
    else:
        tame_distance = other_distance
        wild_distance = this_distance

    normalized_key = tame_distance - wild_distance
    if 0 <= normalized_key <= RANGE_SIZE:
        return PRIVATE_KEY_MIN + normalized_key
    return None


def verify_key(private_key):
    if not PRIVATE_KEY_MIN <= private_key <= PRIVATE_KEY_MAX:
        return False
    compressed_pubkey = private_key_to_compressed_public_key(private_key)
    return compressed_pubkey == COMPRESSED_PUBLIC_KEY


def save_found_key(private_key, worker_id, steps):
    compressed_pubkey = private_key_to_compressed_public_key(private_key)
    address = public_key_to_address(compressed_pubkey)
    wif = private_key_to_wif(private_key)

    with open(FOUND_KEY_FILE, "w") as f:
        f.write(f"Worker: {worker_id}\n")
        f.write(f"Steps: {steps:,}\n")
        f.write(f"Private Key (hex): {hex(private_key)}\n")
        f.write(f"Private Key (raw): {private_key.to_bytes(32, 'big').hex()}\n")
        f.write(f"Private Key (WIF): {wif}\n")
        f.write(f"Compressed Public Key: {compressed_pubkey.hex()}\n")
        f.write(f"Address: {address}\n")

    return address, wif, compressed_pubkey


def record_steps(shared_steps, local_steps):
    if local_steps <= 0:
        return 0
    with shared_steps.get_lock():
        shared_steps.value += local_steps
    return 0


# === Output Reporter ===

def print_progress(shared_found, shared_steps, shared_dp_count, print_lock, start_time, expected_steps):
    ignore_keyboard_interrupt()
    previous_width = 0

    while not shared_found.value:
        time.sleep(1)
        elapsed = time.time() - start_time
        with shared_steps.get_lock():
            steps = shared_steps.value
        with shared_dp_count.get_lock():
            dp_count = shared_dp_count.value

        rate = steps / elapsed if elapsed > 0 else 0
        percent = min((steps / expected_steps) * 100, 100) if expected_steps else 0
        eta = format_eta((expected_steps - steps) / rate) if rate > 0 and expected_steps > steps else "--"
        status = (
            f"{progress_bar(percent)} {percent:6.3f}% | "
            f"{steps:,} steps | {format_rate(rate)}/s | "
            f"DPs {dp_count:,} | {format_time(elapsed)} | ETA {eta}"
        )

        clear_width = max(previous_width, len(status))
        previous_width = len(status)
        with print_lock:
            sys.stdout.write("\r" + status.ljust(clear_width))
            sys.stdout.flush()


# === Kangaroo Search ===

def check_distinguished_point(
    point,
    distance,
    kangaroo_type,
    distinguished_points,
    shared_found,
    shared_steps,
    shared_dp_count,
    print_lock,
    worker_id,
    local_steps,
):
    key = point_key(point)
    previous = distinguished_points.get(key)

    if previous is None:
        distinguished_points[key] = (distance, kangaroo_type)
        with shared_dp_count.get_lock():
            shared_dp_count.value += 1
        return local_steps

    other_distance, other_type = previous
    candidate = derive_candidate(distance, kangaroo_type, other_distance, other_type)
    if candidate is None:
        return local_steps

    if verify_key(candidate):
        local_steps = record_steps(shared_steps, local_steps)
        with shared_found.get_lock():
            if not shared_found.value:
                shared_found.value = True
                with shared_steps.get_lock():
                    total_steps = shared_steps.value
                address, wif, compressed_pubkey = save_found_key(candidate, worker_id, total_steps)
                with print_lock:
                    print(f"\n\n{Fore.GREEN}MATCH FOUND by Worker {worker_id}{Style.RESET_ALL}")
                    print("-" * 60)
                    print(f"Steps:                 {total_steps:,}")
                    print(f"Private Key (hex):     {hex(candidate)}")
                    print(f"Private Key (raw):     {candidate.to_bytes(32, 'big').hex()}")
                    print(f"Private Key (WIF):     {wif}")
                    print(f"Compressed Public Key: {compressed_pubkey.hex()}")
                    print(f"Address:               {address}")
                    print(f"Saved to:              {FOUND_KEY_FILE}")

    return local_steps


def search_key(args):
    (
        worker_id,
        shared_found,
        shared_steps,
        shared_dp_count,
        print_lock,
        dp_bits,
        jump_count,
        batch_size,
    ) = args

    ignore_keyboard_interrupt()
    set_low_priority()

    rng = random.SystemRandom()
    target_point = decompress_pubkey(COMPRESSED_PUBLIC_KEY)
    normalized_target = target_point + (-(PRIVATE_KEY_MIN % N) * G)

    exps, jumps, _ = make_jump_table(jump_count)
    dp_mask = (1 << dp_bits) - 1
    distinguished_points = {}
    local_steps = 0
    last_report = time.time()

    # Shift both walks together so each worker is distinct while the tame walk
    # still starts at the upper bound relative to the wild walk.
    worker_offset = rng.randrange(0, RANGE_SIZE + 1)
    tame_distance = RANGE_SIZE + worker_offset
    wild_distance = worker_offset
    tame_point = tame_distance * G
    wild_point = normalized_target + wild_distance * G

    while not shared_found.value:
        for kangaroo_type in ("tame", "wild"):
            if kangaroo_type == "tame":
                jump_index = tame_point.x() % jump_count
                tame_point += jumps[jump_index]
                tame_distance += exps[jump_index]
                point = tame_point
                distance = tame_distance
            else:
                jump_index = wild_point.x() % jump_count
                wild_point += jumps[jump_index]
                wild_distance += exps[jump_index]
                point = wild_point
                distance = wild_distance

            local_steps += 1
            if point.x() & dp_mask == 0:
                local_steps = check_distinguished_point(
                    point,
                    distance,
                    kangaroo_type,
                    distinguished_points,
                    shared_found,
                    shared_steps,
                    shared_dp_count,
                    print_lock,
                    worker_id,
                    local_steps,
                )

            if local_steps >= batch_size:
                local_steps = record_steps(shared_steps, local_steps)

            if shared_found.value:
                break

        if time.time() - last_report >= 60 + worker_id * 3:
            with print_lock:
                print(
                    f"\n{Fore.LIGHTCYAN_EX}Worker {worker_id}: "
                    f"{len(distinguished_points):,} local DPs"
                    f"{Style.RESET_ALL}"
                )
            last_report = time.time()

    record_steps(shared_steps, local_steps)


# === Self Test ===

def run_self_test():
    test_min = 10_000
    test_max = 120_000
    test_key = 73_451
    fake_range_size = test_max - test_min
    fake_target = test_key * G
    normalized_target = fake_target + (-(test_min % N) * G)

    tame_distance = fake_range_size
    wild_distance = 0
    tame_point = tame_distance * G
    wild_point = normalized_target

    exps = [1, 3, 5, 7, 11, 17, 23, 31]
    jumps = [step * G for step in exps]
    seen = {}

    for _ in range(500_000):
        for kangaroo_type in ("tame", "wild"):
            if kangaroo_type == "tame":
                index = tame_point.x() % len(exps)
                tame_point += jumps[index]
                tame_distance += exps[index]
                point = tame_point
                distance = tame_distance
            else:
                index = wild_point.x() % len(exps)
                wild_point += jumps[index]
                wild_distance += exps[index]
                point = wild_point
                distance = wild_distance

            key = point_key(point)
            previous = seen.get(key)
            if previous is None:
                seen[key] = (distance, kangaroo_type)
                continue

            other_distance, other_type = previous
            if kangaroo_type == other_type:
                continue

            if kangaroo_type == "tame":
                found_key = test_min + distance - other_distance
            else:
                found_key = test_min + other_distance - distance

            if found_key == test_key:
                print(f"{Fore.GREEN}Self-test passed. Kangaroo collision math recovered {test_key}.{Style.RESET_ALL}")
                return True

    print(f"{Fore.RED}Self-test failed. No valid collision found.{Style.RESET_ALL}")
    return False


# === Entry Point ===

def parse_args():
    parser = argparse.ArgumentParser(description="Pollard kangaroo search for Bitcoin Puzzle #135.")
    parser.add_argument("--workers", type=int, help="Number of worker processes.")
    parser.add_argument("--dp-bits", type=int, default=DEFAULT_DP_BITS, help="Distinguished point bit count.")
    parser.add_argument("--jumps", type=int, default=DEFAULT_JUMP_COUNT, help="Jump table size.")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Progress counter batch size.")
    parser.add_argument("--self-test", action="store_true", help="Run a small correctness test and exit.")
    return parser.parse_args()


def validate_target():
    derived = public_key_to_address(COMPRESSED_PUBLIC_KEY)
    if derived != TARGET_BTC_ADDRESS:
        print(f"\n{Fore.RED}Compressed public key does NOT match the target address.{Style.RESET_ALL}")
        print(f"Derived: {derived}")
        print(f"Target:  {TARGET_BTC_ADDRESS}")
        return False
    return True


def main():
    args = parse_args()

    if args.self_test:
        sys.exit(0 if run_self_test() else 1)

    if args.dp_bits < 1 or args.dp_bits > 32:
        print(f"{Fore.RED}--dp-bits must be between 1 and 32.{Style.RESET_ALL}")
        sys.exit(1)

    if args.jumps < 4 or args.jumps > 256:
        print(f"{Fore.RED}--jumps must be between 4 and 256.{Style.RESET_ALL}")
        sys.exit(1)

    if args.batch_size < 1:
        print(f"{Fore.RED}--batch-size must be 1 or greater.{Style.RESET_ALL}")
        sys.exit(1)

    physical, logical = get_cpu_info()
    recommended = max(1, physical - 1)
    _, _, average_jump = make_jump_table(args.jumps)
    expected_steps = max(1, 3 * estimate_sqrt_interval_steps())

    print(f"\n{Fore.CYAN}=== Pollard Kangaroo for Bitcoin Puzzle #135 ==={Style.RESET_ALL}")
    print(f"Target Address: {TARGET_BTC_ADDRESS}")
    print(f"Public Key:     {COMPRESSED_PUBLIC_KEY.hex()}")
    print(f"Range:          {hex(PRIVATE_KEY_MIN)} to {hex(PRIVATE_KEY_MAX)}")
    print(f"Range Size:     {RANGE_SIZE + 1:,} keys")
    print(f"Backend:        {'coincurve' if HAS_COINCURVE else 'ecdsa'}")
    if not HAS_COINCURVE:
        print(f"{Fore.YELLOW}Install coincurve for faster verification: python -m pip install coincurve{Style.RESET_ALL}")
    print(f"DP bits:        {args.dp_bits} (about 1 DP per {1 << args.dp_bits:,} steps)")
    print(f"Jump table:     {args.jumps} jumps, average step about 2^{average_jump.bit_length() - 1}")
    print(f"Expected work:  roughly sqrt(range), around {estimate_sqrt_interval_steps():,} to {expected_steps:,} steps\n")

    if not validate_target():
        sys.exit(1)

    num_workers = args.workers
    if num_workers is None:
        try:
            num_workers = int(
                input(f"{Fore.CYAN}Enter number of workers (1-{physical}, default {recommended}): {Style.RESET_ALL}")
                or recommended
            )
        except ValueError:
            print(f"{Fore.RED}Invalid worker count.{Style.RESET_ALL}")
            sys.exit(1)

    if not 1 <= num_workers <= physical:
        print(f"{Fore.RED}Workers must be between 1 and {physical}.{Style.RESET_ALL}")
        sys.exit(1)

    if num_workers == physical:
        print(f"{Fore.YELLOW}Using all physical cores may impact system responsiveness. Starting in 3s...{Style.RESET_ALL}")
        time.sleep(3)

    if set_low_priority():
        print("Process priority: below normal")

    shared_found = Value("b", False)
    shared_steps = Value("Q", 0)
    shared_dp_count = Value("Q", 0)
    print_lock = Lock()

    start_time = time.time()
    printer = Process(
        target=print_progress,
        args=(shared_found, shared_steps, shared_dp_count, print_lock, start_time, expected_steps),
    )
    printer.start()

    workers = []
    stopped_by_user = False

    try:
        for worker_id in range(num_workers):
            process = Process(
                target=search_key,
                args=(
                    (
                        worker_id,
                        shared_found,
                        shared_steps,
                        shared_dp_count,
                        print_lock,
                        args.dp_bits,
                        args.jumps,
                        args.batch_size,
                    ),
                ),
            )
            process.start()
            workers.append(process)

        for process in workers:
            process.join()
    except KeyboardInterrupt:
        stopped_by_user = True
        with shared_found.get_lock():
            shared_found.value = True
        with print_lock:
            print(f"\n{Fore.YELLOW}Stopping search...{Style.RESET_ALL}")
    finally:
        for process in workers:
            if process.is_alive():
                process.terminate()
            process.join()

        printer.terminate()
        printer.join()
        print()

    if stopped_by_user:
        print(f"{Fore.YELLOW}Search stopped by user.{Style.RESET_ALL}")
    elif shared_found.value:
        print(f"{Fore.GREEN}Search completed successfully.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Search ended without finding the key.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
