import hashlib
import sys
import argparse
import requests
import csv
import os
from typing import List
from getpass import getpass


def request_api_data(query_char: str) -> requests.Response:
    """Query the Pwned Passwords API using the first 5 characters of the SHA-1 hash."""
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        return res
    except requests.RequestException as e:
        raise RuntimeError(f'Error fetching data: {e}')


def get_password_leaks_count(hashes: requests.Response, hash_to_check: str) -> int:
    """Check if the tail hash is found in the API response."""
    hashes = (line.split(':') for line in hashes.text.splitlines())
    return next((int(count) for h, count in hashes if h == hash_to_check), 0)


def pwned_api_check(password: str) -> int:
    """Check the password against the Pwned Passwords API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def process_passwords(passwords: List[str], output_csv: str = None) -> None:
    """Check all passwords and optionally write to CSV."""
    results = []

    for pw in passwords:
        pw = pw.strip()
        if not pw:
            print("[!] Skipping empty password.")
            continue
        try:
            count = pwned_api_check(pw)
            masked_pw = pw[:2] + '*' * (len(pw) - 4) + pw[-2:] if len(pw) > 4 else '*' * len(pw)
            if count:
                print(f'[!!] Password "{masked_pw}" was found {count} times! Consider changing it.')
            else:
                print(f'[OK]  Password "{masked_pw}" was NOT found. Looks safe.')
            results.append((masked_pw, count))
        except Exception as e:
            print(f"[ERROR] Failed to check password: {e}")
            results.append((pw, "Error"))

    if output_csv:
        try:
            with open(output_csv, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Password', 'Times Found'])
                writer.writerows(results)
            print(f'\n[+] Results written to {output_csv}')
        except IOError as e:
            print(f'[ERROR] Could not write to CSV: {e}')


def read_passwords_from_file(file_path: str) -> List[str]:
    """Read passwords from a plaintext file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'File not found: {file_path}')
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file if line.strip()]


def get_args():
    parser = argparse.ArgumentParser(description='Check if your password(s) have been pwned using the Have I Been Pwned API.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--passwords', nargs='+', help='Password(s) to check')
    group.add_argument('-f', '--file', help='File containing passwords (one per line)')
    group.add_argument('--prompt', action='store_true', help='Secure prompt to enter a password interactively')
    parser.add_argument('--csv', help='Optional: Save results to a CSV file')
    return parser.parse_args()


def main():
    args = get_args()

    if args.prompt:
        password = getpass('Enter your password securely: ')
        process_passwords([password], output_csv=args.csv)
    elif args.passwords:
        process_passwords(args.passwords, output_csv=args.csv)
    elif args.file:
        try:
            pw_list = read_passwords_from_file(args.file)
            process_passwords(pw_list, output_csv=args.csv)
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)


if __name__ == '__main__':
    main()

