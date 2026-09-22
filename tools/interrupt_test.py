"""portscan.py 的 Ctrl+C 中断回归测试(F6)。

selftest.py 测不了 Ctrl+C：它用 subprocess 启动子进程，
而 Windows 上给子进程发 Ctrl+C 事件要 AttachConsole 那一套，
又脆又平台相关。

换个思路：在【本进程内】用 runpy 跑 portscan.py 的 main，
再用 _thread.interrupt_main() 从另一个线程给主线程抛 KeyboardInterrupt ——
效果和用户按 Ctrl+C 一样，但不依赖任何终端。

用法:
    cd D:\\Code\\security-lab
    .\\.venv\\Scripts\\python.exe tools\\interrupt_test.py

验证两件事:
  1. 退出码是 130 (128 + SIGINT)，不是 0、也不是 traceback。
  2. "Interrupted: N ports scanned" 里的 N 是【真正扫完的】端口数，
     和打印了几行无关。
"""
import io
import os
import runpy
import sys
import threading
import time
import _thread
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "portscan.py")

# 135 是开放的(秒回)，8000-8004 无响应(各耗满 timeout)。
# -t 1 保证串行，中断时机的可预测性最好。
BASE_ARGS = ["127.0.0.1", "-p", "135,8000-8004", "--timeout", "1", "-t", "1"]
INTERRUPT_AFTER = 2.5   # 秒。此时 135 + 8000 + 8001 应已完成
EXPECT_DONE = 3


def run_once(extra_args):
    """在本进程里跑一次 portscan，中途触发 KeyboardInterrupt。

    返回 (退出码, 结果行列表, stderr 文本)
    """
    sys.argv = ["portscan.py"] + BASE_ARGS + extra_args

    def killer():
        time.sleep(INTERRUPT_AFTER)
        _thread.interrupt_main()

    threading.Thread(target=killer, daemon=True).start()

    out_buf, err_buf = io.StringIO(), io.StringIO()
    code = None
    try:
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            runpy.run_path(SCRIPT, run_name="__main__")
        code = 0
    except SystemExit as e:
        code = e.code

    # 结果行长这样: "127.0.0.1:135 open"
    lines = [ln for ln in out_buf.getvalue().splitlines() if ":" in ln]
    return code, lines, err_buf.getvalue()


def main():
    failed = 0
    want_msg = f"Interrupted: {EXPECT_DONE} ports scanned"

    scenarios = (
        ([], "默认(filtered 不打印)", 1),
        (["--show-filtered"], "加 --show-filtered", 3),
    )

    for extra, label, want_lines in scenarios:
        print(f"--- {label} ---")
        code, lines, err = run_once(extra)
        for ln in lines:
            print(f"    打印: {ln}")

        problems = []
        if code != 130:
            problems.append(f"退出码 {code}, 期望 130")
        if len(lines) != want_lines:
            problems.append(f"打印 {len(lines)} 个端口, 期望 {want_lines}")
        if want_msg not in err:
            problems.append(f"stderr 里缺少 {want_msg!r}, 实际: {err.strip()!r}")

        if problems:
            failed += 1
            print("    FAIL")
            for p in problems:
                print(f"      - {p}")
        else:
            print(f"    ok  (打印 {len(lines)} 个端口, "
                  f"报告扫过 {EXPECT_DONE} 个)")
        print()

    print(f'两次的 stderr 都是 "Interrupted: {EXPECT_DONE} ports scanned before '
          f'you pressed Ctrl+C"。')
    print("第一次只打印 1 行却报告 3 —— 这就是要守住的区别：")
    print("计数统计的是【扫过多少】，不是【打印几行】。")
    print()

    if failed:
        print(f"===== {failed} 个场景失败 =====")
        sys.exit(1)
    print("===== 全部通过 =====")


if __name__ == "__main__":
    main()
