import requests
import hashlib
import ecdsa
import base58
import time
import sys
import psutil
import random
import os
import queue
import signal
from multiprocessing import (
    Pool, Value, cpu_count, Manager, freeze_support
)

# Try to import coincurve for faster ECC operations
try:
    from coincurve import PrivateKey as CoincurvePrivateKey
    HAS_COINCURVE = True
except ImportError:
    CoincurvePrivateKey = None
    HAS_COINCURVE = False

# --- Configuration ---
TARGET_BTC_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# Pre-calculate the target 20-byte Hash160 to avoid Base58 decoding in the loop
TARGET_HASH160 = base58.b58decode_check(TARGET_BTC_ADDRESS)[1:]

# Private key range for Puzzle 71 (2^70 to 2^71 - 1)
PRIVATE_KEY_MIN = 0x400000000000000000
PRIVATE_KEY_MAX = 0x7FFFFFFFFFFFFFFFFF

# Script Directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Shared State Globals (Initialized in main)
found = None
keys_checked = None
chunk_counter = None
random_chunk_queue = None
random_history_lock = None

# Chunk Sizes
SUB_RANGE_SIZE = 2**20       # 1,048,576 keys
RANDOM_SUB_RANGE_SIZE = 2**18 # 262,144 keys

# File Paths
RANDOM_HISTORY_FILE = r"E:\puzzle71_random_done.txt"
FOUND_KEY_FILE = os.path.join(SCRIPT_DIR, "found_key_71.txt")

def ignore_keyboard_interrupt():
    """Ignore Ctrl+C in worker processes to allow graceful shutdown."""
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass

def init_worker(shared_found, shared_keys_checked, shared_chunk_counter):
    global found, keys_checked, chunk_counter
    ignore_keyboard_interrupt()
    found = shared_found
    keys_checked = shared_keys_checked
    chunk_counter = shared_chunk_counter
    set_low_priority()

def init_random_worker(
    shared_found,
    shared_keys_checked,
    shared_random_chunk_queue,
    shared_random_history_lock,
):
    global found, keys_checked, random_chunk_queue, random_history_lock
    ignore_keyboard_interrupt()
    found = shared_found
    keys_checked = shared_keys_checked
    random_chunk_queue = shared_random_chunk_queue
    random_history_lock = shared_random_history_lock
    set_low_priority()

# --- Utility Functions ---

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
    except Exception:
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

def format_percent(value):
    if value == 0:
        return "0%"
    if value < 0.000001:
        return f"{value:.12f}%"
    if value < 0.01:
        return f"{value:.8f}%"
    return f"{value:.6f}%"

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

            for private_key in range(sub_range_min, sub_range_max + 1):
                if found.value:
                    break
                try:
                    compressed_public_key = private_key_to_compressed_public_key(private_key)
                    
                    sha256_bpk = hashlib.sha256(compressed_public_key).digest()
                    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
                    
                    local_count += 1
                    
                    # Batch update shared counter to reduce lock contention
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
                except Exception:
                    continue
                    
            if local_count > 0:
                with keys_checked.get_lock():
                    keys_checked.value += local_count
                local_count = 0
                
        except Exception:
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
        
        
        for private_key in range(sub_range_min, sub_range_max + 1):
            if found.value:
                completed_chunk = False
                break
            try:

                compressed_public_key = private_key_to_compressed_public_key(private_key)
                
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

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from datetime import datetime

class Puzzle71GUI:
    BG, CARD, SOFT = "#202124", "#292a2d", "#34363a"
    FG, MUTED, TEAL = "#f1f3f4", "#bdc1c6", "#75d6b2"

    def __init__(self, root):
        self.root = root
        root.title("Puzzle 71 · 搜索面板")
        root.geometry("980x880")
        root.minsize(800, 820)
        root.configure(bg=self.BG)
        try:
            root.attributes("-alpha", 0.85)
        except tk.TclError:
            pass
        self.physical, self.logical = get_cpu_info()
        self.choice = tk.StringVar(value="first")
        self.workers = tk.StringVar(value="1")
        self.random_n = tk.StringVar(value="100")
        self.status = tk.StringVar(value="准备就绪")
        self.checked = tk.StringVar(value="0")
        self.speed = tk.StringVar(value="—")
        self.elapsed = tk.StringVar(value="00:00:00")
        self.eta = tk.StringVar(value="—")
        self.address_balance = tk.StringVar(value="读取中…")
        self.address_activity = tk.StringVar(value="正在读取最近活动…")
        self.address_status = tk.StringVar(value="")
        self.active = self.stop_requested = self.closing = False
        self.total = 0
        self.prepared_random_chunks = None
        self.random_summary_job = None
        self.random_history_mtime = None
        self.current_search_mode = None
        self._ui()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(300, self.refresh_address_activity)
        self.refresh()

    def _on_mousewheel(self, event):
        self.scroll_canvas.yview_scroll(int(-event.delta / 120), "units")
        return "break"

    def label(self, parent, text="", **kw):
        return tk.Label(parent, text=text, bg=kw.pop("bg", self.CARD), fg=kw.pop("fg", self.FG),
                        font=kw.pop("font", ("Microsoft YaHei UI", 10)), **kw)

    def _ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=self.SOFT, background=self.TEAL,
                        bordercolor=self.SOFT, lightcolor=self.TEAL, darkcolor=self.TEAL)
        container = tk.Frame(self.root, bg=self.BG)
        container.pack(fill="both", expand=True)
        canvas = tk.Canvas(container, bg=self.BG, highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=self.BG, padx=26, pady=22)
        body_window = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_window, width=event.width))
        self.scroll_canvas = canvas
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)
        self.root.bind_all("<Button-4>", lambda _event: self.scroll_canvas.yview_scroll(-3, "units"))
        self.root.bind_all("<Button-5>", lambda _event: self.scroll_canvas.yview_scroll(3, "units"))
        self.label(body, "谜题 71", bg=self.BG, fg=self.TEAL,
                   font=("Microsoft YaHei UI", 10)).pack(anchor="w")
        self.label(body, "比特币谜题搜索", bg=self.BG,
                   font=("Microsoft YaHei UI", 25)).pack(anchor="w", pady=(2, 0))
        self.label(body, "多进程搜索 · 实时运行状态", bg=self.BG,
                   fg=self.MUTED).pack(anchor="w", pady=(0, 16))
        addr = tk.Frame(body, bg=self.SOFT, padx=15, pady=12)
        addr.pack(fill="x", pady=(0, 14))
        self.label(addr, "目标地址", bg=self.SOFT, fg=self.MUTED,
                   font=("Microsoft YaHei UI", 8)).pack(anchor="w")
        self.label(addr, TARGET_BTC_ADDRESS, bg=self.SOFT,
                   font=("Consolas", 11)).pack(anchor="w", pady=(4, 0))
        address_card = tk.Frame(body, bg=self.CARD, padx=18, pady=12)
        address_card.pack(fill="x", pady=(0, 12))
        address_head = tk.Frame(address_card, bg=self.CARD)
        address_head.pack(fill="x")
        self.label(address_head, "地址余额与最近活动", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        self.label(address_card, textvariable=self.address_balance, fg=self.TEAL,
                   font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w", pady=(7, 2))
        self.label(address_card, textvariable=self.address_activity, fg=self.MUTED,
                   font=("Microsoft YaHei UI", 9), justify="left", anchor="w",
                   wraplength=900).pack(fill="x", anchor="w")
        self.label(address_card, textvariable=self.address_status, fg=self.MUTED,
                   font=("Microsoft YaHei UI", 8)).pack(anchor="w", pady=(3, 0))

        row = tk.Frame(body, bg=self.BG)
        row.pack(fill="x", pady=(0, 14))
        setup = tk.Frame(row, bg=self.CARD, padx=18, pady=15)
        setup.pack(fill="x")
        self.label(setup, "搜索设置", font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w")
        self.label(setup, "选择搜索范围与并行进程数", fg=self.MUTED,
                   font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(3, 8))
        choices = tk.Frame(setup, bg=self.CARD)
        choices.pack(fill="x")
        for index, (value, caption) in enumerate((("first", "前 1/3"), ("middle", "中间 1/3"),
                                                   ("end", "后 1/3"), ("random", "随机小分块"))):
            tk.Radiobutton(choices, text=caption, variable=self.choice, value=value,
                           command=self.toggle_random, bg=self.CARD, fg=self.FG,
                           selectcolor=self.SOFT, activebackground=self.CARD,
                           activeforeground=self.TEAL,
                           font=("Microsoft YaHei UI", 10)).grid(
                               row=index // 4, column=index % 4, sticky="w", padx=(0, 24), pady=3)
        controls = tk.Frame(setup, bg=self.CARD)
        controls.pack(anchor="w", pady=(8, 0))
        self.label(controls, "并行进程", font=("Microsoft YaHei UI", 9, "bold")).grid(
            row=0, column=0, sticky="w")
        self.work_box = ttk.Combobox(
            controls, textvariable=self.workers, state="readonly", width=8,
            values=[str(i) for i in range(1, max(1, self.physical) + 1)])
        self.work_box.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.label(controls, "随机小分块数量", font=("Microsoft YaHei UI", 9, "bold")).grid(
            row=0, column=1, sticky="w", padx=(18, 0))
        self.random_entry = tk.Entry(
            controls, textvariable=self.random_n, width=12, bg=self.SOFT,
            fg=self.FG, insertbackground=self.FG, relief="flat",
            font=("Microsoft YaHei UI", 10), state="disabled")
        self.random_entry.grid(row=1, column=1, sticky="w", padx=(18, 0), pady=(4, 0), ipady=6)
        self.random_n.trace_add("write", lambda *_: self.schedule_random_summary())
        self.random_summary = tk.Frame(body, bg=self.CARD, padx=18, pady=12)
        self.label(self.random_summary, "随机任务摘要", font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w")
        self.random_summary_text = tk.StringVar(value="选择随机小分块模式后显示任务与历史记录。")
        self.label(self.random_summary, textvariable=self.random_summary_text, fg=self.MUTED,
                   font=("Microsoft YaHei UI", 9), justify="left", anchor="w",
                   wraplength=900).pack(fill="x", anchor="w", pady=(7, 0))
        self.random_summary.pack(fill="x", pady=(0, 14))
        self.random_summary.pack_forget()
        monitor = tk.Frame(body, bg=self.CARD, padx=18, pady=15)
        monitor.pack(fill="x", pady=(0, 14))
        self.monitor = monitor
        self.label(monitor, "运行监控", font=("Microsoft YaHei UI", 12)).pack(anchor="w")
        self.bar = ttk.Progressbar(monitor, maximum=100)
        self.bar.pack(fill="x", pady=(12, 14))
        stats = tk.Frame(monitor, bg=self.CARD)
        stats.pack(fill="x")
        for title, var in (("已检查", self.checked), ("速度", self.speed),
                           ("运行时间", self.elapsed), ("预计剩余", self.eta)):
            cell = tk.Frame(stats, bg=self.CARD)
            cell.pack(side="left", expand=True, fill="x")
            self.label(cell, title, fg=self.MUTED, font=("Microsoft YaHei UI", 8)).pack(anchor="w")
            self.label(cell, textvariable=var, font=("Microsoft YaHei UI", 12)).pack(anchor="w", pady=(3, 0))
        footer = tk.Frame(body, bg=self.BG)
        footer.pack(fill="x")
        self.label(footer, textvariable=self.status, bg=self.BG, fg=self.TEAL).pack(side="left")
        self.button = tk.Button(footer, text="开始搜索", command=self.start,
                                bg=self.TEAL, fg="#07131b", activebackground="#76e7d2",
                                relief="flat", padx=22, pady=10, cursor="hand2",
                                font=("Microsoft YaHei UI", 10))
        self.button.pack(side="right")

    def refresh_address_activity(self):
        self.address_status.set("正在读取区块链数据…")
        threading.Thread(target=self._fetch_address_activity, daemon=True).start()

    def _fetch_address_activity(self):
        try:
            api_base = "https://blockstream.info/api"
            headers = {"User-Agent": "Puzzle71GUI/1.0"}
            address_response = requests.get(
                f"{api_base}/address/{TARGET_BTC_ADDRESS}", headers=headers, timeout=15)
            address_response.raise_for_status()
            address_data = address_response.json()
            chain_stats = address_data.get("chain_stats", {})
            mempool_stats = address_data.get("mempool_stats", {})
            balance_satoshis = (
                int(chain_stats.get("funded_txo_sum", 0))
                - int(chain_stats.get("spent_txo_sum", 0))
                + int(mempool_stats.get("funded_txo_sum", 0))
                - int(mempool_stats.get("spent_txo_sum", 0))
            )
            balance = balance_satoshis / 100_000_000
            transactions_response = requests.get(
                f"{api_base}/address/{TARGET_BTC_ADDRESS}/txs", headers=headers, timeout=15)
            transactions_response.raise_for_status()
            transactions = transactions_response.json()
            rows = []
            for tx in transactions[:3]:
                received = sum(
                    int(output.get("value", 0))
                    for output in tx.get("vout", [])
                    if output.get("scriptpubkey_address") == TARGET_BTC_ADDRESS
                )
                spent = sum(
                    int(tx_input.get("prevout", {}).get("value", 0))
                    for tx_input in tx.get("vin", [])
                    if tx_input.get("prevout", {}).get("scriptpubkey_address") == TARGET_BTC_ADDRESS
                )
                net_satoshis = received - spent
                amount = abs(net_satoshis) / 100_000_000
                direction = "转入" if net_satoshis > 0 else ("转出" if net_satoshis < 0 else "净额为 0")
                timestamp = int(tx.get("status", {}).get("block_time", 0))
                when = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M") if timestamp else "未确认"
                rows.append(f"{when} | {direction} | {amount:.8f} BTC")
            if not rows:
                rows = ["暂无交易记录"]
            result = (f"当前余额：{balance:.8f} BTC", "\n".join(rows),
                      f"数据更新时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as exc:
            result = ("当前余额：读取失败", f"最近活动读取失败：{exc}", "下次打开程序时会重新读取。")
        self.root.after(0, lambda values=result: self._show_address_activity(values))

    def _show_address_activity(self, values):
        self.address_balance.set(values[0])
        self.address_activity.set(values[1])
        self.address_status.set(values[2])

    def toggle_random(self):
        random_mode = self.choice.get() == "random"
        self.random_entry.configure(state="normal" if random_mode and not self.active else "disabled")
        if random_mode:
            if not self.random_summary.winfo_manager():
                self.random_summary.pack(fill="x", pady=(0, 14), before=self.monitor)
            if not self.active:
                self.schedule_random_summary()
        else:
            self.random_summary.pack_forget()
            self.prepared_random_chunks = None
            self._cancel_random_summary()

    def _cancel_random_summary(self):
        if self.random_summary_job is not None:
            try:
                self.root.after_cancel(self.random_summary_job)
            except tk.TclError:
                pass
            self.random_summary_job = None

    def schedule_random_summary(self):
        if self.choice.get() != "random" or self.active:
            return
        self._cancel_random_summary()
        self.random_summary_job = self.root.after(350, self.update_random_summary)

    def update_random_summary(self):
        self.random_summary_job = None
        if self.choice.get() != "random":
            return None
        try:
            try:
                requested = int(self.random_n.get().strip())
            except ValueError:
                raise ValueError("请输入有效的随机小分块数量。")
            if requested < 1:
                raise ValueError("随机小分块数量必须至少为 1。")
            completed = load_random_history()
            self.random_history_mtime = os.path.getmtime(RANDOM_HISTORY_FILE) if os.path.exists(RANDOM_HISTORY_FILE) else None
            chunks = build_random_session_chunks(requested, completed)
            full_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
            completed_keys = random_chunks_key_count(completed)
            session_keys = random_chunks_key_count(chunks)
            estimates = " · ".join(
                f"{format_rate(rate)}/秒 {format_eta(session_keys / rate)}"
                for rate in (10_000, 20_000, 45_000, 100_000)
            )
            self.random_summary_text.set(
                f"小分块大小：{RANDOM_SUB_RANGE_SIZE:,} 个密钥\n"
                f"历史已完成：{len(completed):,} 个分块 · {completed_keys:,} 个密钥 · "
                f"占完整范围 {format_percent(completed_keys / full_keys * 100)}\n"
                f"本次准备：{len(chunks):,} 个分块 · {session_keys:,} 个密钥 · "
                f"占完整范围 {format_percent(session_keys / full_keys * 100)}\n"
                f"预计耗时：{estimates}\n"
                f"运行方式：本次准备的小分块全部处理完成后结束\n"
                f"历史记录：{RANDOM_HISTORY_FILE}"
            )
            self.prepared_random_chunks = chunks
            return chunks
        except (OSError, ValueError) as exc:
            message = str(exc)
            if "Every random mini chunk" in message:
                message = "所有随机小分块都已记录为完成。"
            self.prepared_random_chunks = None
            self.random_summary_text.set(f"无法准备随机任务：{message}")
            return None
    def refresh_random_history(self):
        try:
            updated_mtime = os.path.getmtime(RANDOM_HISTORY_FILE)
        except OSError:
            return
        if updated_mtime == self.random_history_mtime:
            return
        try:
            completed = load_random_history()
        except OSError:
            return
        self.random_history_mtime = updated_mtime
        full_keys = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
        completed_keys = random_chunks_key_count(completed)
        lines = self.random_summary_text.get().splitlines()
        if len(lines) > 1:
            lines[1] = (
                f"历史已完成：{len(completed):,} 个分块 · {completed_keys:,} 个密钥 · "
                f"占完整范围 {format_percent(completed_keys / full_keys * 100)}"
            )
            self.random_summary_text.set("\n".join(lines))

    def start(self):
        global found, keys_checked, chunk_counter
        if self.active:
            self.stop()
            return
        try:
            nworkers = int(self.workers.get())
            if not 1 <= nworkers <= self.physical:
                raise ValueError(f"并行进程数需在 1 到 {self.physical} 之间。")
            mode = self.choice.get()
            if mode == "random":
                self._cancel_random_summary()
                chunks = self.update_random_summary()
                if chunks is None:
                    raise ValueError(self.random_summary_text.get())
                self.total = random_chunks_key_count(chunks)
                search_mode, bounds = "random", (PRIVATE_KEY_MIN, PRIVATE_KEY_MAX)
            else:
                full = PRIVATE_KEY_MAX - PRIVATE_KEY_MIN + 1
                third = full // 3
                lo, hi = {"first": (0, third - 1), "middle": (third, 2 * third - 1), "end": (2 * third, full - 1)}[mode]
                bounds = (PRIVATE_KEY_MIN + lo, PRIVATE_KEY_MIN + hi)
                self.total = bounds[1] - bounds[0] + 1
                search_mode, chunks = "deterministic", None
        except (ValueError, KeyError) as exc:
            messagebox.showerror("设置有误", str(exc), parent=self.root)
            return
        found, keys_checked, chunk_counter = Value('b', False), Value('Q', 0), Value('Q', 0)
        self.current_search_mode = search_mode
        self.started = time.time()
        self.stop_requested = False
        self.active = True
        self.button.configure(text="停止搜索", bg="#ed7a83")
        self.work_box.configure(state="disabled")
        self.toggle_random()
        threading.Thread(target=self.run, args=(nworkers, search_mode, bounds, chunks), daemon=True).start()

    def run(self, nworkers, mode, bounds, chunks):
        global found, keys_checked, chunk_counter
        try:
            if mode == "random":
                with Manager() as manager:
                    q = manager.Queue()
                    for chunk in chunks:
                        q.put(chunk)
                    lock = manager.Lock()
                    with Pool(nworkers, initializer=init_random_worker,
                              initargs=(found, keys_checked, q, lock)) as pool:
                        wait_for_pool(pool, search_key_random, [(i,) for i in range(nworkers)])
            else:
                with Pool(nworkers, initializer=init_worker,
                          initargs=(found, keys_checked, chunk_counter)) as pool:
                    wait_for_pool(pool, search_key_chunked, [(i, bounds[0], bounds[1]) for i in range(nworkers)])
            outcome = "stopped" if self.stop_requested else ("found" if found.value else "complete")
        except Exception as exc:
            outcome = f"error: {exc}"
        self.root.after(0, lambda: self.finish(outcome))

    def stop(self):
        global found
        self.stop_requested = True
        if found is not None:
            with found.get_lock():
                found.value = True
        self.status.set("正在停止进程…")

    def finish(self, result):
        self.active = False
        self.button.configure(text="开始搜索", bg=self.TEAL)
        self.work_box.configure(state="readonly")
        self.toggle_random()
        labels = {"stopped": "搜索已停止；已完成的随机分块已保存。",
                  "complete": "本次搜索已完成，所选范围内未发现匹配项。",
                  "found": f"已找到匹配项，详情已保存至 {os.path.basename(FOUND_KEY_FILE)}"}
        self.status.set(labels.get(result, result))
        if result == "found":
            self.show_result()
        if result.startswith("error:"):
            messagebox.showerror("搜索出错", result[7:].strip(), parent=self.root)
        if self.closing:
            self.root.destroy()

    def show_result(self):
        try:
            with open(FOUND_KEY_FILE, "r", encoding="utf-8") as result_file:
                details = result_file.read()
        except OSError as exc:
            messagebox.showerror("找到匹配项", f"无法读取结果文件：{exc}", parent=self.root)
            return
        field_names = {
            "Worker": "工作进程", "Random Chunk": "随机分块",
            "Keys Checked": "已检查密钥数", "Private Key (Hex)": "私钥（Hex）",
            "Private Key (Raw)": "私钥（Raw）", "Private Key (WIF)": "私钥（WIF）",
            "Compressed Public Key": "压缩公钥", "Bitcoin Address": "比特币地址",
            "Balance": "余额",
        }
        localized_lines = []
        for line in details.splitlines():
            key, separator, value = line.partition(":")
            localized_lines.append(f"{field_names.get(key, key)}{separator}{value}")
        details = "\n".join(localized_lines)
        window = tk.Toplevel(self.root)
        window.title("搜索结果 · 找到匹配项")
        window.geometry("650x420")
        window.configure(bg=self.CARD)
        self.label(window, "找到匹配项", fg=self.TEAL,
                   font=("Microsoft YaHei UI", 17)).pack(anchor="w", padx=18, pady=(18, 10))
        output = tk.Text(window, bg=self.SOFT, fg=self.FG, insertbackground=self.FG,
                         relief="flat", wrap="word", font=("Consolas", 10), padx=12, pady=12)
        output.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        output.insert("1.0", details)
        output.configure(state="disabled")

    def refresh(self):
        if self.active:
            with keys_checked.get_lock():
                count = keys_checked.value
            elapsed = max(time.time() - self.started, .001)
            rate = count / elapsed
            self.checked.set(f"{count:,} / {self.total:,}")
            self.speed.set(f"{format_rate(rate)} / 秒")
            self.elapsed.set(format_time(elapsed))
            self.eta.set(format_eta(max(self.total - count, 0) / rate) if rate else "计算中…")
            self.bar.configure(value=min(100, count * 100 / self.total))
            if found.value and not self.stop_requested:
                self.status.set("已发现匹配项，正在查询余额并保存结果…")
            if self.current_search_mode == "random":
                self.refresh_random_history()
        self.root.after(500, self.refresh)

    def close(self):
        if self.active:
            self.closing = True
            self.stop()
        else:
            self.root.destroy()

def main():
    global found, keys_checked, chunk_counter
    freeze_support()
    found = keys_checked = chunk_counter = None
    root = tk.Tk()
    Puzzle71GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()