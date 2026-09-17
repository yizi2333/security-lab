import requests
import argparse
import sys
from urllib.parse import urljoin
from urllib.parse import urlsplit

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL or host")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=5, help="Request timeout")
    args = parser.parse_args()
    base = normal_target(args.target)

    try:
        check_target(base, args.timeout)
    except TargetError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.wordlist, encoding="utf-8") as f:
        seen = set()
        for line in f:
            path = line.split("#")[0].strip()
            if not path:
                continue
            if path in seen:
                continue
            seen.add(path)
            url = urljoin(base, path)
            try:
                r = requests.get(url, allow_redirects=False, timeout=args.timeout)
            except requests.RequestException as e:
                print(f"Error {url} ({type(e).__name__})", file=sys.stderr)
                continue
            print(r.status_code, url)

if __name__ == "__main__":
    main()
