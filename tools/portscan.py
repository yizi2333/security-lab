import socket
import argparse
import sys

class PortParseError(ValueError):

    pass

class Port:
    protocol = "TCP"
    MIN = 1
    MAX = 65535
    def __init__(self, number, service=""):
        if not (Port.MIN <= number <= Port.MAX):
            raise PortParseError(f"port out of range ({Port.MIN}-{Port.MAX}): {number}")
        self.number = number
        self.service = service


    @classmethod
    def parse(cls, text):
        text = text.strip()
        if "-" in text:
            pieces = text.split("-")

            if len(pieces) != 2:
                raise PortParseError(f"invalid port range format: {text}")
            try:
                start, end = map(int, pieces)
            except ValueError:
                raise PortParseError(f"invalid port range values: {text}")
            if start > end:
                raise PortParseError(f"invalid port range: {text}")
            return [cls(n) for n in range(start, end + 1)]
        
        try: 
            n = int(text)
        except ValueError:
            raise PortParseError(f"invalid port value: {text}") from None
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
    def scan_port(host, port):

        if not isinstance(port, Port):
            raise TypeError(f"expected Port, got {type(port).__name__}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            try:
                s.connect((host, port.number))
            except OSError:
                return False
            return True

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan (comma-separated)")
    args = parser.parse_args()
    host = args.target
    try:
        ports = parse_ports(args.ports)
    except PortParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Cannot resolve hostname: {host}")
        sys.exit(1) 

    for port in ports: 
        if Port.scan_port(host, port):
            print(f"{host}:{port} open")
        else:
            print(f"{host}:{port} closed")
