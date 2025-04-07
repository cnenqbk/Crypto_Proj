import requests
import time
import sys
import random

def read_addresses(filename):
    """Read Bitcoin addresses from a file"""
    try:
        with open(filename, 'r') as file:
            addresses = [line.strip() for line in file if line.strip()]
        return addresses
    except FileNotFoundError:
        print(f"\nError: File '{filename}' not found.")
        sys.exit(1)

def check_balance(address):
    """Check balance using blockchain.info API"""
    try:
        url = f"https://blockchain.info/balance?active={address}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if address in data:
            balance = data[address]['final_balance'] / 100000000
            return balance
        return None
    except Exception as e:
        print(f"\nAPI Error for {address}: {str(e)}")
        return None

def display_all_addresses(addresses):
    """Check and display all addresses"""
    valid_count = 0
    total_balance = 0.0
    
    print("\nChecking ALL addresses...")
    print("-" * 60)
    print(f"{'Address':42} {'Balance (BTC)':>15}")
    print("-" * 60)
    
    for i, address in enumerate(addresses, 1):
        balance = check_balance(address)
        
        if balance is not None:
            print(f"{address:42} {balance:15.8f}")
            if balance <= 1.0:
                valid_count += 1
                total_balance += balance
        else:
            print(f"{address:42} {'Error':>15}")
        
        print(f"Progress: {i}/{len(addresses)} | Valid (≤1 BTC): {valid_count}", end="\r")
        time.sleep(1)
    
    print("\n\n" + "-" * 60)
    print(f"Total addresses: {len(addresses)}")
    print(f"Valid addresses (≤1 BTC): {valid_count}")
    print(f"Total valid balance: {total_balance:.8f} BTC")
    print("-" * 60)

def find_random_valid(addresses, target_count=20):
    """Randomly find valid addresses"""
    valid_addresses = []
    checked_count = 0
    random.shuffle(addresses)
    
    print("\nRandomly searching for 20 addresses with ≤1 BTC...")
    print("-" * 60)
    print(f"{'Address':42} {'Balance (BTC)':>15}")
    print("-" * 60)
    
    for address in addresses:
        if len(valid_addresses) >= target_count:
            break
            
        balance = check_balance(address)
        checked_count += 1
        
        if balance is not None:
            if balance <= 1.0:
                valid_addresses.append((address, balance))
                print(f"{address:42} {balance:15.8f}")
            else:
                print(f"{address:42} {balance:15.8f} (Skipped)")
        else:
            print(f"{address:42} {'Error':>15}")
        
        print(f"Checked: {checked_count} | Found: {len(valid_addresses)}/{target_count}", end="\r")
        time.sleep(1)
    
    print("\n\n" + "-" * 60)
    print("Final Results (≤1 BTC balances):")
    print("-" * 60)
    total_balance = sum(balance for _, balance in valid_addresses)
    
    for address, balance in valid_addresses:
        print(f"{address:42} {balance:15.8f}")
    
    print("-" * 60)
    print(f"Found: {len(valid_addresses)} addresses")
    print(f"Total balance: {total_balance:.8f} BTC")
    print(f"Average balance: {total_balance/len(valid_addresses):.8f} BTC" if valid_addresses else "No balances found")
    print("-" * 60)

def main():
    input_file = "lists.txt"
    
    print(f"Reading addresses from {input_file}...")
    addresses = read_addresses(input_file)
    print(f"Found {len(addresses)} addresses")
    
    # Display menu
    print("\nChoose an option:")
    print("1. Check ALL addresses (shows all balances)")
    print("2. Find 20 random addresses with ≤1 BTC balance (faster)")
    
    while True:
        choice = input("Enter your choice (1 or 2): ").strip()
        if choice in ('1', '2'):
            break
        print("Invalid input! Please enter 1 or 2.")
    
    if choice == '1':
        display_all_addresses(addresses)
    else:
        find_random_valid(addresses)

if __name__ == "__main__":
    main()