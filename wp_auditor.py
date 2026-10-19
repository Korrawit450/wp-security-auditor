import sys
import re
import requests
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/") + "/"

def check_wp_version(target_url: str):
    print(f"\n{Fore.CYAN}[*] Checking WordPress Version Exposure...{Style.RESET_ALL}")
    
    # 1. เช็กจาก meta tag ในหน้าแรก
    try:
        res = requests.get(target_url, headers=HEADERS, timeout=8)
        match = re.search(r'content="WordPress ([0-9.]+)"', res.text, re.IGNORECASE)
        if match:
            print(f"  {Fore.RED}[!] Vulnerable:{Style.RESET_ALL} Version exposed in Meta Tag -> {Fore.YELLOW}{match.group(1)}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+] Secure:{Style.RESET_ALL} Version hidden from Meta Tag.")
    except requests.exceptions.RequestException:
        print(f"  {Fore.RED}[-] Failed to query homepage.{Style.RESET_ALL}")

    # 2. เช็กจาก readme.html
    readme_url = urljoin(target_url, "readme.html")
    try:
        res = requests.get(readme_url, headers=HEADERS, timeout=8)
        if res.status_code == 200 and "wordpress" in res.text.lower():
            print(f"  {Fore.RED}[!] Vulnerable:{Style.RESET_ALL} Publicly accessible readme file -> {readme_url}")
        else:
            print(f"  {Fore.GREEN}[+] Secure:{Style.RESET_ALL} readme.html is inaccessible (HTTP {res.status_code}).")
    except requests.exceptions.RequestException:
        pass

def check_user_enumeration(target_url: str):
    print(f"\n{Fore.CYAN}[*] Testing User Enumeration via WP REST API...{Style.RESET_ALL}")
    api_url = urljoin(target_url, "wp-json/wp/v2/users")
    
    try:
        res = requests.get(api_url, headers=HEADERS, timeout=8)
        if res.status_code == 200:
            try:
                users = res.json()
                if isinstance(users, list) and len(users) > 0:
                    usernames = [u.get("slug") for u in users if "slug" in u]
                    print(f"  {Fore.RED}[!] Vulnerable:{Style.RESET_ALL} REST API exposes usernames: {Fore.YELLOW}{', '.join(usernames)}{Style.RESET_ALL}")
                    print(f"      Recommendation: Disable /wp-json/wp/v2/users for unauthenticated requests.")
                    return
            except ValueError:
                pass
        print(f"  {Fore.GREEN}[+] Secure:{Style.RESET_ALL} User endpoint is disabled or protected.")
    except requests.exceptions.RequestException:
        print(f"  {Fore.RED}[-] Connection failed during user enum check.{Style.RESET_ALL}")

def check_sensitive_files(target_url: str):
    print(f"\n{Fore.CYAN}[*] Checking Sensitive Files & Endpoints...{Style.RESET_ALL}")
    checks = [
        ("xmlrpc.php", "XML-RPC API (Susceptible to brute force & DDoS attacks)"),
        ("wp-login.php", "Default login page exposed"),
        ("wp-config.php.bak", "Backup configuration file"),
        (".env", "Environment configuration file")
    ]
    
    for path, description in checks:
        full_url = urljoin(target_url, path)
        try:
            res = requests.get(full_url, headers=HEADERS, timeout=8, allow_redirects=False)
            if res.status_code == 200:
                print(f"  {Fore.RED}[!] Found (HTTP 200):{Style.RESET_ALL} {path:<18} -> {description}")
            elif res.status_code in [301, 302]:
                print(f"  {Fore.YELLOW}[~] Redirect (HTTP {res.status_code}):{Style.RESET_ALL} {path:<18}")
            else:
                print(f"  {Fore.GREEN}[+] Protected (HTTP {res.status_code}):{Style.RESET_ALL} {path:<18}")
        except requests.exceptions.RequestException:
            continue

def main():
    if len(sys.argv) < 2:
        print("Usage: python wp_auditor.py <target-url>")
        sys.exit(1)

    target_url = normalize_url(sys.argv[1])
    print(f"{Fore.MAGENTA}=== WordPress Security Auditor ==={Style.RESET_ALL}")
    print(f"Target: {target_url}")

    check_wp_version(target_url)
    check_user_enumeration(target_url)
    check_sensitive_files(target_url)
    
    print(f"\n{Fore.MAGENTA}=== Audit Completed ==={Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()