import re
import sys
import argparse
from datetime import datetime
from collections import Counter
from urllib.parse import urlsplit

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus",
    "dirbuster", "gobuster", "wfuzz", "ffuf", "hydra",
    "curl", "wget", "python-requests", "go-http-client",
]

SENSITIVE_PATHS = [
    "/.env", "/.git", "/backup", "/config.php", "/phpinfo.php",
    "/.htaccess", "/db.sql", "/wp-config.php", "/admin/config.php",
]

BRUTE_PATHS = ["/admin/login.php", "/wp-login.php", "/login", "/admin/"]

SCAN_404_THRESHOLD = 10
BRUTE_THRESHOLD = 10


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", help="Path to access log")
    args = parser.parse_args()

    ok = 0
    bad = 0
    ip_counter = Counter()
    path_counter = Counter()
    status_counter = Counter()
    ip_404_counter = Counter()
    ua_counter = Counter()
    ip_ua = {}
    ip_brute = Counter()
    ip_sensitive = Counter()
    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                bad += 1
                continue
            m = LOG_RE.search(line)
            if not m:
                bad += 1
                continue
            ip = m.group("ip")
            status = m.group("status")
            path = urlsplit(m.group("path")).path
            ua = m.group("ua") or ""
            try:
                dt = datetime.strptime(m.group("time"), TIME_FMT)
            except ValueError:
                bad += 1
                continue

            ip_counter[ip] += 1
            path_counter[path] += 1
            status_counter[status] += 1
            ua_counter[ua] += 1
            ip_ua.setdefault(ip, set()).add(ua)
            if status == "404":
                ip_404_counter[ip] += 1
            if path in BRUTE_PATHS:
                ip_brute[ip] += 1
            if any(path.startswith(s) for s in SENSITIVE_PATHS):
                ip_sensitive[ip] += 1
            ok += 1

    print(f"总请求数   : {ok}")
    print(f"跳过行数   : {bad}")
    print(f"独立 IP 数 : {len(ip_counter)}")
    print()
    print("Top 5 访问 IP:")
    for ip, n in ip_counter.most_common(5):
        print(f"  {n:>5}  {ip}")
    print()
    print("Top 5 请求路径:")
    for path, n in path_counter.most_common(5):
        print(f"  {n:>5}  {path}")
    print()
    print("状态码分布:")
    for status, n in sorted(status_counter.items()):
        print(f"  {status}: {n}")
    print()
    print("404 最多的 IP:")
    for ip, n in ip_404_counter.most_common(5):
        print(f"  {n:>5}  {ip}")

    print()
    print("=" * 62)
    print("  可疑行为")
    print("=" * 62)

    print()
    print(f"[1] 疑似目录扫描(404 次数 >= {SCAN_404_THRESHOLD})")
    hits = [(ip, n) for ip, n in ip_404_counter.most_common()
            if n >= SCAN_404_THRESHOLD]
    if hits:
        for ip, n in hits:
            print(f"    {ip:16} {n:>5} 次 404")
    else:
        print("    未发现")

    print()
    print(f"[2] 疑似暴力破解(打登录路径 >= {BRUTE_THRESHOLD} 次)")
    hits = [(ip, n) for ip, n in ip_brute.most_common()
            if n >= BRUTE_THRESHOLD]
    if hits:
        for ip, n in hits:
            print(f"    {ip:16} {n:>5} 次 登录请求")
    else:
        print("    未发现")

    print()
    print("[3] 扫描器特征 User-Agent")
    found = False
    for ip in sorted(ip_ua):
        hits = set()
        for ua in ip_ua[ip]:
            low = ua.lower()
            for kw in SUSPICIOUS_UA:
                if kw in low:
                    hits.add(kw)
        if hits:
            found = True
            n_req = ip_counter[ip]
            print(f"    {ip:16} {n_req:>5} 次请求   命中 {len(hits)} 种: "
                  f"{','.join(sorted(hits))}")
    if not found:
        print("    未发现")

    print()
    print("[4] 敏感路径探测")
    hits = [(ip, n) for ip, n in ip_sensitive.most_common() if n > 0]
    if hits:
        for ip, n in hits:
            print(f"    {ip:16} {n:>5} 次 敏感路径")
    else:
        print("    未发现")

    print()
    print("=" * 62)

if __name__ == "__main__":
    main()