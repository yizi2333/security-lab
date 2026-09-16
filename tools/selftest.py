"""portscan.py 的自测脚本。

用法:
    cd D:\\Code\\security-lab
    .\\.venv\\Scripts\\python.exe tools\\selftest.py

全部通过会打印 OK;有失败会列出哪一条错了。
"""
import subprocess
import sys
import os

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "portscan.py")

# (命令行参数, 期望退出码, 期望输出里必须包含的字符串列表, 说明)
CASES = [
    (["127.0.0.1", "-p", "135"], 0, ["127.0.0.1:135 open"], "单个开放端口"),
    (["127.0.0.1", "-p", "1"], 0, ["127.0.0.1:1 closed"], "单个关闭端口"),
    (["127.0.0.1", "-p", "135,445"], 0, ["127.0.0.1:135 open", "127.0.0.1:445 open"], "两个端口"),
    (["127.0.0.1", "-p", "8000-8003"], 0, ["127.0.0.1:8000 closed",
                                           "127.0.0.1:8001 closed",
                                           "127.0.0.1:8002 closed",
                                           "127.0.0.1:8003 closed"], "端口范围展开成 4 个"),
    (["127.0.0.1", "-p", "135-135"], 0, ["127.0.0.1:135"], "退化范围只扫一个"),
    (["127.0.0.1", "-p", "abc"], 1, ["Error"], "非数字 -> 友好报错"),
    (["127.0.0.1", "-p", "99999"], 1, ["Error"], "超范围 -> 友好报错"),
    (["127.0.0.1", "-p", "0"], 1, ["Error"], "端口 0 -> 友好报错"),
    (["127.0.0.1", "-p", "100-50"], 1, ["Error"], "反向范围 -> 友好报错"),
    (["127.0.0.1", "-p", "80-"], 1, ["Error"], "缺尾数字 -> 友好报错"),
    (["127.0.0.1", "-p", "80-90-100"], 1, ["Error"], "三段范围 -> 友好报错"),
    (["127.0.0.1", "-p", "135,135"], 1, ["Error"], "重复端口 -> 友好报错"),
    (["no-such-host-abcxyz.invalid", "-p", "80"], 1, ["resolve"], "域名解析失败 -> 友好报错"),
    (["127.0.0.1", "-p", "135", "-t", "0"], 1, ["Error"], "-t 0 -> 友好报错"),
    (["127.0.0.1", "-p", "135", "-t", "1"], 0, ["127.0.0.1:135 open"], "-t 1 单线程仍正确"),
    (["127.0.0.1/32", "-p", "135"], 0, ["127.0.0.1:135 open"], "CIDR /32"),
    (["127.0.0.1/30", "-p", "135"], 0, ["127.0.0.1:135 open",
                                        "127.0.0.2:135 open"], "CIDR /30 两台主机"),
    (["abc/24", "-p", "80"], 1, ["Error"], "非法 CIDR -> 友好报错"),
    (["10.0.0.0/8", "-p", "80"], 1, ["Error"], "网段过大 -> 友好报错"),
]

# 输出里绝对不能出现的东西
FORBIDDEN = ["Traceback", "object at 0x"]


def run(args, limit=30):
    p = subprocess.Popen([PY, SCRIPT] + args, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True,
                         encoding="utf-8", errors="replace")
    try:
        out, _ = p.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return None, out or "", True
    return p.returncode, out or "", False


def main():
    failed = 0
    for args, want_rc, want_text, desc in CASES:
        rc, out, timed_out = run(args)

        problems = []
        if timed_out:
            problems.append("超时(可能是死循环)")
        if rc != want_rc:
            problems.append(f"退出码 {rc},期望 {want_rc}")
        for t in want_text:
            if t not in out:
                problems.append(f"输出里缺少 {t!r}")
        for bad in FORBIDDEN:
            if bad in out:
                problems.append(f"输出里出现了不该有的 {bad!r}")

        if problems:
            failed += 1
            print(f"FAIL  {desc}")
            for pr in problems:
                print(f"        - {pr}")
            print("        实际输出:")
            for line in out.splitlines():
                print(f"          {line}")
        else:
            print(f"ok    {desc}")

    print()
    if failed:
        print(f"===== {failed} / {len(CASES)} 个用例失败 =====")
        sys.exit(1)
    print(f"===== 全部 {len(CASES)} 个用例通过 =====")


if __name__ == "__main__":
    main()
