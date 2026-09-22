import socket
import argparse
import sys
import signal
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

MAX_HOSTS = 1024

class PortParseError(ValueError):

    pass

class TargetParseError(ValueError):

    pass

class Port:
    protocol = "TCP"
    MIN = 1
    MAX = 65535
    def __init__(self, number, service=""):
        #端口号必须在合法范围内
        if not (Port.MIN <= number <= Port.MAX):
            raise PortParseError(f"Port out of range ({Port.MIN}-{Port.MAX}): {number}")
        self.number = number
        self.service = service

    #拆解端口范围
    @classmethod
    def parse(cls, text):
        text = text.strip()
        if "-" in text:
            pieces = text.split("-")

            #端口范围必须是两段
            if len(pieces) != 2:
                raise PortParseError(f"Invalid port range format: {text}")
            try:
                start, end = map(int, pieces)
                #端口范围必须合法
            except ValueError:
                raise PortParseError(f"Invalid port range values: {text}") from None
                #端口范围必须不反向
            if start > end:
                raise PortParseError(f"Invalid port range: {text}")
            return [cls(n) for n in range(start, end + 1)]
        
        try: 
            n = int(text)
            #端口范围必须合法
        except ValueError:
            raise PortParseError(f"Invalid port value: {text}") from None
        return [cls(n)]

    def __eq__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.number == other.number

    def __hash__(self):
        return hash(self.number)

    def __str__(self):
        return f"{self.number}/{self.service}" if self.service else str(self.number)

    def __repr__(self):
        return f"Port({self.number})"

    @staticmethod
    def scan_port(host, port, timeout):

        #排除非 Port 类型
        if not isinstance(port, Port):
            raise TypeError(f"Expected Port, got {type(port).__name__}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((host, port.number))
            except OSError:
                return False
            return True

#去除重复端口
def parse_ports(port_str):
    seen = set()
    result = []
    for part in port_str.split(","):
        for port in Port.parse(part):
            if port in seen:
                raise PortParseError(f"Duplicate port: {port}")
            seen.add(port)
            result.append(port)
    return result

#返回 (host, port, 是否开放)
def check_one(target, timeout):
    host, port = target
    return host, port, Port.scan_port(host, port, timeout)

#解析目标，支持 CIDR 和主机名
def parse_target(text):
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise TargetParseError(f"Invalid CIDR: {text}") from None
        if net.prefixlen >= 31:
            n = net.num_addresses
        else:
            n = net.num_addresses - 2  #排除网络地址和广播地址
        if n > MAX_HOSTS:
            raise TargetParseError(f"CIDR too large: {text} ({n} hosts, max {MAX_HOSTS})")
        return net.hosts()

    try :
        net = socket.gethostbyname(text)
        return [net]
    except socket.gaierror:
        raise TargetParseError(f"Cannot resolve hostname: {text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan (comma-separated)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=2, help="Connection timeout in seconds")
    args = parser.parse_args()
    target = args.target
    timeout = args.timeout


    if args.threads <= 0:
        print(f"Error: threads must be positive, got {args.threads}", file=sys.stderr)
        sys.exit(1)

    if args.timeout <= 0:
        print(f"Error: timeout must be positive, got {args.timeout}", file=sys.stderr)
        sys.exit(1)

    worker = partial(check_one, timeout=args.timeout)

    try:
        ports = parse_ports(args.ports)
    except PortParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        targets = parse_target(target)
    except TargetParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    #使用迭代器生成所有 (host, port) 组合，避免内存占用过大
    jobs = ((str(host), port) for host in targets for port in ports)
    #调用check_one(host, port)
    executor = ThreadPoolExecutor(max_workers=args.threads)
    done = 0
    try:
        # 用 as_completed 而不是 map:
        #   map 按【提交顺序】交付, 一个慢任务会卡住整条结果流,
        #   导致 Ctrl+C 时可能一个结果都还没拿到。
        #   as_completed 按【完成顺序】交付, 谁先扫完谁先打印,
        #   所以中断时能看到真实进度(代价是输出不按输入顺序)。
        futures = [executor.submit(worker, job) for job in jobs]
        for fut in as_completed(futures):
            host, port, is_open = fut.result()
            state = "open" if is_open else "closed"
            print(f"{host}:{port} {state}")
            done += 1
    except KeyboardInterrupt:
        # Ctrl+C: 取消还没开始的任务, 不等它们
        executor.shutdown(wait=False, cancel_futures=True)
        print()
        print(f"Interrupted: {done} ports scanned before you pressed Ctrl+C",
              file=sys.stderr)
        sys.exit(128 + signal.SIGINT)
    else:
        executor.shutdown(wait=True)

    print()
    print(f"Done: {done} ports scanned")
