import requests
import argparse
import sys
from urllib.parse import urljoin
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from collections import Counter
import time

class TargetError(ValueError):
    pass

def normal_target(target):
    if urlsplit(target).scheme not in ("http", "https"):
        target = "http://" + target
    return target

def check_target(base, timeout):
    try:
        requests.get(base, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        raise TargetError(f"Cannot connect to {base} ({type(e).__name__})") from None

def fmt_duration(sec):
    """把秒数格式化成人类友好的形式。"""
    if sec < 60:
        return f"{sec:.2f} 秒"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{int(m)} 分 {s:.1f} 秒"
    h, m = divmod(m, 60)
    return f"{int(h)} 时 {int(m)} 分"

def worker(target, session, timeout):
    base, path = target
    url = urljoin(base, path)
    try:
        r = session.get(url, allow_redirects=False, timeout=timeout)
        return path, r.status_code, None
    except requests.RequestException as e:
        return path, None, type(e).__name__
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL or host")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")
    parser.add_argument("--show-404", action="store_true", help="Show 404 results (default: hidden)")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()
    base = normal_target(args.target)

    try:
        check_target(base, args.timeout)
    except TargetError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    paths = []
    seen = set()
    with open(args.wordlist, encoding="utf-8") as f:
        for line in f:
            path = line.split("#")[0].strip()
            if not path or path in seen:
                continue
            seen.add(path)
            paths.append(path)
            
    t0 = time.perf_counter()

    with requests.Session() as session:
        session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        job_worker = partial(worker, session=session, timeout=args.timeout)

        jobs = ((base, p) for p in paths)
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            results = list(executor.map(job_worker, jobs))

    dt = time.perf_counter() - t0

    out_file = open(args.output, "w", encoding="utf-8") if args.output else None
    try:
        for path, code, err in results:
            url = urljoin(base, path)
            if err:
                print(f"! ERR  {url}  ({err})", file=sys.stderr)
                continue
            if code == 404 and not args.show_404:
                continue
            mark = "*" if code in (200, 301, 302, 401, 403) else " "
            print(f"{mark} {code:>3}  {url}")
            if out_file:
                out_file.write(f"{code} {url}\n")
    finally:
        if out_file:
            out_file.close()

    codes = Counter(c for _, c, _ in results if c is not None)
    errors = sum(1 for _, _, e in results if e)

    print()
    print("-" * 72)
    rows = [
        ("请求总数", len(results)),
        ("失败", errors),
        ("耗时", fmt_duration(dt)),
    ]
    w = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {k:<{w}} : {v}")
    print()
    print("  状态码分布:")
    for c in sorted(codes):
        bar = "#" * min(codes[c], 50)
        note = "" if (c != 404 or args.show_404) else "   (已隐藏)"
        print(f"    {c:>3}  {codes[c]:>4}  {bar}{note}")
    print()
    print("=" * 72)
    

if __name__ == "__main__":
    main()
