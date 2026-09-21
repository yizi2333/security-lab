from datetime import datetime, timedelta
import argparse
import sys
import random
from collections import Counter
 
# 路径 -> (状态码, 资源类型)
NORMAL_PATHS = {
    "/":                (200, "page"),
    "/index.html":      (200, "page"),
    "/about.html":      (200, "page"),
    "/contact.html":    (200, "page"),
    "/articles/1":      (200, "page"),
    "/articles/2":      (200, "page"),
    "/articles/3":      (200, "page"),
    "/search?q=test":   (200, "query"),
    "/search?q=python": (200, "query"),
    "/page/2":          (200, "page"),
    "/css/style.css":   (200, "static"),
    "/js/app.js":       (200, "static"),
    "/images/logo.png": (200, "static"),
}

SCAN_PATHS = ["/admin", "/administrator", "/backup", "/dashboard", "/db",
              "/includes", "/install", "/manage", "/old", "/private",
              "/setup", "/test", "/tmp", "/uploads", "/vendor", "/wp-admin",
              "/wp-content", "/wp-login.php", "/xmlrpc.php", "/api/v1"
]

BRUTE_PATHS = ["/admin/login.php", "/wp-login.php", "/login", "/admin/"
]

SENSITIVE_PATHS = ["/.env", "/.git/config", "/backup/db.sql", "/config.php",
                   "/phpinfo.php", "/.htaccess", "/admin/config.php"
]

NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

BOT_UA = ["Googlebot/2.1 (+http://www.google.com/bot.html)",
          "bingbot/2.0 (+http://www.bing.com/bingbot.htm)"
]

SCANNER_UA = ["sqlmap/1.7#stable (http://sqlmap.org)",
              "Nikto/2.5.0", "masscan/1.3", "Nmap Scripting Engine",
              "python-requests/2.34.2", "curl/8.4.0"
]

NUM_USERS = 20

def pick_status(base_status, kind):
    #按资源类型决定是否偏离常态
    if random.random() >= 0.03:
        return base_status
    # 3% 的偏离, 但要按类型选择合理的异常
    if kind == "static":
        return 404
    if kind == "query":
        return random.choice([500, 200])

    return random.choice([301, 301, 500])

def gen_line(dt, ip, path, ua, status, size):
    """把各个字段拼成一段日志"""
    time_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0800")
    return (f'{ip} - - [{time_str}] '
            f'"GET {path} HTTP/1.1" ' 
            f'{status} {size} "-" "{ua}"')

def gen_scan(entries, n, ip, start, seconds):
    """目录扫描: 一个 IP 短时间打大量路径"""
    for _ in range(n):
        path = random.choice(SCAN_PATHS)
        dt = start + timedelta(seconds=random.randint(0, seconds))
        status = random.choices([404,403,200,301], weights=[80, 5, 10, 5])[0]
        size = random.randint(100, 50000)
        line = gen_line(dt, ip, path, random.choice(SCANNER_UA), status, size)
        entries.append((dt, line))

def gen_brute(entries, n ,ip, start, seconds):
    """暴力破解: 反复请求登录接口"""
    for _ in range(n):
        path = random.choice(BRUTE_PATHS)       # 只有 4 个路径, 反复用
        dt = start + timedelta(seconds=random.randint(0, seconds))
        # 登录尝试多是失败 -> 401/403
        status = random.choices([401, 403, 302, 200], weights=[65, 15, 15, 5])[0]
        size = random.randint(800, 3000)
        line = gen_line(dt, ip, path, random.choice(SCANNER_UA), status, size)
        entries.append((dt, line))

def gen_sensitive(entries, n ,ip, start, seconds):
    """敏感文件探测: 打 /.env /.git/config 这类"""
    for _ in range(n):
        path = random.choice(SENSITIVE_PATHS)       # 7 个敏感路径
        dt = start + timedelta(seconds=random.randint(0, seconds))
        status = random.choices([401, 403, 302, 200], weights=[65, 15, 15, 5])[0]
        size = random.randint(800, 3000)
        line = gen_line(dt, ip, path, random.choice(SCANNER_UA), status, size)
        entries.append((dt, line))

def gen_scanner_ua(entries, n, ip, start, seconds):
    """扫描器特征 UA: 固定用一个明显的扫描器 UA"""
    for _ in range(n):
        path = random.choice(SCAN_PATHS + SENSITIVE_PATHS)
        dt = start + timedelta(seconds=random.randint(0, seconds))
        status = random.choices([200, 404], weights=[30, 70])[0]
        size = random.randint(100, 3000)
        # 固定 UA, 方便验证"UA 检测规则"命中
        line = gen_line(dt, ip, path, "sqlmap/1.7#stable (http://sqlmap.org)",
                        status, size)
        entries.append((dt, line))

def gen_broken(n, sample_line):
    """生成 n 行损坏内容，返回字符串列表（没有时间戳）"""
    out = []
    for _ in range(n):
        kind = random.choices(["truncate", "empty", "no_brackets",
                               "wrong_time", "syslog", "short"], k=1)[0]
        if kind == "truncate":
            out.append(sample_line[:random.randint(20, 60)])
        elif kind == "empty":
            out.append("")
        elif kind == "no_brackets":
            out.append(sample_line.replace("[", "").replace("]", ""))
        elif kind == "wrong_time":
            out.append(sample_line.replace("Sep/2026", "09/2026"))
        elif kind == "syslog":
            out.append("Sep 17 10:03:35 webserver kernel: "
                       "[12345.678] eth0: link up")
        else:
            out.append(sample_line[:random.randint(8, 20)])
    return out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lines", type=int, default=1000, help="Total lines to gennerate")
    parser.add_argument("--out", default="access.log", help="Output file")
    args = parser.parse_args()

    if args.lines <=0:
        print(f"Error: lines must be positive, got {args.lines}", file=sys.stderr)
        sys.exit(1)

    total = args.lines
    n_normal = int(total * 0.70)
    n_scan = int(total * 0.15)
    n_brute = int(total * 0.05)
    n_sens = int(total * 0.03)
    n_scanner = int(total * 0.02)
    n_broken  = total - (n_normal + n_scan + n_brute + n_sens + n_scanner)

    entries = []

    users = [f"192.168.1.{random.randint(2, 254)}" for _ in range(NUM_USERS)]
    # 时间窗口
    start = datetime(2026, 9, 17, 10, 0, 0)
    end = datetime(2026, 9, 17, 12, 0, 0)
    span = int((end - start).total_seconds())

    for _ in range(n_normal):
        path = random.choice(list(NORMAL_PATHS))
        base_status, kind = NORMAL_PATHS[path]
        status = pick_status(base_status,kind)


        dt = start + timedelta(seconds=random.randint(0, span))
        ip = random.choice(users)
        ua = random.choice(NORMAL_UA)
        size = random.randint(200,50000)

        line = gen_line(dt, ip, path, ua, status, size)
        entries.append((dt, line))

    gen_scan(entries, n_scan, "10.0.0.66",
             datetime(2026, 9, 17, 11, 30, 0), 30)
    gen_brute(entries, n_brute, "10.0.0.77",
              datetime(2026, 9, 17, 11, 40, 0), 60)
    gen_sensitive(entries, n_sens, "10.0.0.88",
                  datetime(2026, 9, 17, 11, 45, 0), 20)
    gen_scanner_ua(entries, n_scanner, "10.0.0.99",
                   datetime(2026, 9, 17, 11, 50, 0), 40)

    entries.sort(key=lambda x: x[0])
    lines = [line for _, line in entries]       # 拆出纯字符串

    # 生成损坏行(字符串列表, 没有时间)
    sample_line = gen_line(start, "192.168.1.11", "/index.html",
                           NORMAL_UA[0], 200, 5428)
    broken = gen_broken(n_broken, sample_line)

    # 随机插进 lines
    for b in broken:
        pos = random.randint(0, len(lines))
        lines.insert(pos, b)

    with open(args.out, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")

    print(f"生成 {len(lines)} 行 -> {args.out}")
    ip_count = Counter(line.split()[0] for _, line in entries)
    print()
    print("  实际统计(从生成的数据里数出来的):")
    for ip in ["10.0.0.66", "10.0.0.77", "10.0.0.88", "10.0.0.99"]:
        print(f"    {ip:12} {ip_count[ip]:>5} 行")

if __name__ == "__main__":
    main()