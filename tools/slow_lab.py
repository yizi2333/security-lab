"""模拟'远程服务器'的靶场: 每个响应延迟 50ms。
用来观察 dirscan.py 在不同线程数下的耗时差异。

用法:
    .\\.venv\\Scripts\\python.exe tools\\slow_lab.py
"""
import http.server
import socketserver
import time

PORT = 8103
DELAY = 0.05          # 50ms, 接近真实远程服务器的往返延迟


class SlowHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        time.sleep(DELAY)                     # 模拟网络 + 服务端处理耗时
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with ThreadedServer(("127.0.0.1", PORT), SlowHandler) as httpd:
    print(f"slow lab on http://127.0.0.1:{PORT}  (每个响应延迟 {DELAY*1000:.0f}ms)")
    print("Ctrl+C to stop")
    httpd.serve_forever()
