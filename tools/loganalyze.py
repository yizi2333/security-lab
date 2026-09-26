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
# 同一个 IP 这个次数以上出现 "password=" 在 URL 里 -> 疑似爆破
PWD_IN_URL_THRESHOLD = 10
SQLI_KEYWORDS = ['union', 'select', 'order by']
SQLI_THRESHOLD = 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", help="Path to access log")
    parser.add_argument("--top", type=int, default=5,
                        help="Show top N IPs and paths (default: 5)")
    parser.add_argument("-o", "--output", help="Write report to file")
    args = parser.parse_args()

    if args.top <= 0:
        print(f"Error: --top must be positive, got {args.top}", file=sys.stderr)
        sys.exit(1)

    ok = 0
    bad = 0
    ip_counter = Counter()
    path_counter = Counter()
    status_counter = Counter()
    ip_404_counter = Counter()
    ua_counter = Counter()
    ip_sqli = Counter()
    ip_ua = {}
    ip_brute = Counter()
    ip_sensitive = Counter()
    ip_ua_hit = Counter()      # 真正命中扫描器 UA 的请求数(按 IP)
    ip_pwd = Counter()         # URL 查询串里含 password= 的请求数(按 IP)
    internal = 0               # 服务器内部连接(OPTIONS *), 不是用户流量
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
            # 请求目标是 "*" 的, 是服务器自己发的内部连接(OPTIONS *),
            # 不是用户流量。单独计数, 不能混进 bad —— bad 的意思是"解析失败"。
            if m.group("path") == "*":
                internal += 1
                continue
            ip = m.group("ip")
            status = m.group("status")
            target = urlsplit(m.group("path"))
            path = target.path
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
            # 只有真正带扫描器特征的请求才计数 (原来错用了 ip_counter[ip])
            low_ua = ua.lower()
            if any(kw in low_ua for kw in SUSPICIOUS_UA):
                ip_ua_hit[ip] += 1
            # 凭据出现在 URL 查询串里
            if "password=" in target.query.lower():
                ip_pwd[ip] += 1
            if status == "404":
                ip_404_counter[ip] += 1
            if path in BRUTE_PATHS:
                ip_brute[ip] += 1
            if any(path.startswith(s) for s in SENSITIVE_PATHS):
                ip_sensitive[ip] += 1
            low_query = target.query.lower()
            if '%27' in low_query and any(kw in low_query for kw in SQLI_KEYWORDS):
                ip_sqli[ip] += 1
            ok += 1

    def emit(text=""):
        print(text)
        if out_file is not None:
            out_file.write(text + "\n")

    out_file = open(args.output, "w", encoding="utf-8") if args.output else None
    try:
        emit(f"总请求数   : {ok}")
        emit(f"跳过行数   : {bad}")
        emit(f"内部连接数 : {internal}   (OPTIONS *, 服务器自己发的, 不算用户流量)")
        emit(f"独立 IP 数 : {len(ip_counter)}")
        emit()
        emit(f"Top {args.top} 访问 IP:")
        for ip, n in ip_counter.most_common(args.top):
            emit(f"  {n:>5}  {ip}")
        emit()
        emit(f"Top {args.top} 请求路径:")
        for path, n in path_counter.most_common(args.top):
            emit(f"  {n:>5}  {path}")
        emit()
        emit("状态码分布:")
        for status, n in sorted(status_counter.items()):
            emit(f"  {status}: {n}")
        emit()
        emit(f"404 最多的 IP(Top {args.top}):")
        for ip, n in ip_404_counter.most_common(args.top):
            emit(f"  {n:>5}  {ip}")

        emit()
        emit("=" * 62)
        emit("  可疑行为")
        emit("=" * 62)

        emit()
        emit(f"[1] 疑似目录扫描(404 次数 >= {SCAN_404_THRESHOLD})")
        hits = [(ip, n) for ip, n in ip_404_counter.most_common()
                if n >= SCAN_404_THRESHOLD]
        if hits:
            for ip, n in hits:
                emit(f"    {ip:16} {n:>5} 次 404")
        else:
            emit("    未发现")

        emit()
        emit(f"[2] 疑似暴力破解(打登录路径 >= {BRUTE_THRESHOLD} 次)")
        hits = [(ip, n) for ip, n in ip_brute.most_common()
                if n >= BRUTE_THRESHOLD]
        if hits:
            for ip, n in hits:
                emit(f"    {ip:16} {n:>5} 次 登录请求")
        else:
            emit("    未发现")

        emit()
        emit("[3] 扫描器特征 User-Agent")
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
                # 这里必须用"真正命中扫描器 UA 的请求数",
                # 而不是这个 IP 的总请求数 —— 否则报告会把正常流量算成攻击。
                n_hit = ip_ua_hit[ip]
                n_all = ip_counter[ip]
                emit(f"    {ip:16} {n_hit:>5} 次命中(该 IP 共 {n_all} 次请求)"
                     f"   命中 {len(hits)} 种: {','.join(sorted(hits))}")
        if not found:
            emit("    未发现")

        emit()
        emit("[4] 敏感路径探测")
        hits = [(ip, n) for ip, n in ip_sensitive.most_common() if n > 0]
        if hits:
            for ip, n in hits:
                emit(f"    {ip:16} {n:>5} 次 敏感路径")
        else:
            emit("    未发现")

        emit()
        emit(f"[5] 凭据出现在 URL 中(查询串含 password= , >= {PWD_IN_URL_THRESHOLD} 次)")
        hits = [(ip, n) for ip, n in ip_pwd.most_common()
                if n >= PWD_IN_URL_THRESHOLD]
        if hits:
            for ip, n in hits:
                emit(f"    {ip:16} {n:>5} 次")
        else:
            emit("    未发现")
        emit("    说明: 凭据出现在 URL 里本身就是缺陷(会被 access log、")
        emit("          浏览器历史、Referer 记录)。高频出现则是爆破特征。")
        emit("          这里无法区分「正常 GET 登录」和「爆破」—— 只能靠频率。")

        emit()
        emit(f"[6] SQL注入探测(查询串含 '以及UNION , >= {SQLI_THRESHOLD} 次)")
        sql_hits = [(ip, n) for ip, n in ip_sqli.most_common()
                    if n >= SQLI_THRESHOLD]
        if sql_hits:
            for ip, n in sql_hits:
                emit(f"    {ip:16} {n:>5} 次")
        else:
            emit("    未发现")

        emit("=" * 62)
        emit()
    finally:
        if out_file is not None:
            out_file.close()

if __name__ == "__main__":
    main()