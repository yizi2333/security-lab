"""生成目录扫描器的测试靶场和字典文件。

用法:
    cd D:\\Code\\security-lab
    .\\.venv\\Scripts\\python.exe tools\\setup_lab.py

会创建:
    lab\\                 本地靶场的网站根目录
    wordlists\\common.txt  一张小字典(约 60 条)
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------- 靶场文件: 路径 -> 内容 ----------
# 注意: 有些路径故意做成"不返回 200",用来测试状态码处理
LAB_FILES = {
    # --- 返回 200,内容正常 ---
    "index.html": "<h1>Home</h1>",
    "about.html": "<h1>About</h1>",
    "contact.html": "<h1>Contact</h1>",
    "login.php": "<?php // login form ?>",
    "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
    "sitemap.xml": "<urlset></urlset>",
    "README.md": "# internal notes",
    "uploads/": None,                    # 目录占位
    "images/": None,
    "css/": None,
    "js/": None,
    "css/style.css": "body{}",
    "js/app.js": "console.log(1)",
    "images/logo.png": "PNG",
    # --- 后台/敏感路径(也是 200,现实中很危险) ---
    "admin/": None,
    "admin/index.php": "<?php // admin panel ?>",
    "admin/login.php": "<?php // admin login ?>",
    "admin/config.php": "<?php // db config ?>",
    "backup/": None,
    "backup/db.sql": "-- dump",
    "backup/site.zip": "PK",
    "config.php": "<?php // config ?>",
    "db.php": "<?php // db ?>",
    ".env": "DB_PASSWORD=secret",
    ".git/": None,
    ".git/config": "[core]\n",
    "phpinfo.php": "<?php phpinfo(); ?>",
    "server-status": "Apache Status",
    "api/": None,
    "api/v1/": None,
    "api/v1/users": '{"users":[]}',
    "test/": None,
    "test/index.html": "<h1>test</h1>",
    "tmp/": None,
    "logs/": None,
    "logs/error.log": "2026-01-01 ERROR something",
    "install/": None,
    "install/index.php": "<?php // installer ?>",
}

# 字典文件内容(给扫描器用)
# 注意: 故意混进一些不存在于靶场的路径,让扫描结果有"找到了"和"没找到"两种
WORDLIST = """admin
admin/
admin/index.php
admin/login.php
admin/config.php
administrator
api
api/
api/v1/
api/v1/users
about.html
backup
backup/
backup/db.sql
backup/site.zip
config
config.php
contact.html
css
css/
css/style.css
dashboard
data
db.php
docs
download
images
images/
images/logo.png
include
includes
index.html
index.php
install
install/
install/index.php
js
js/
js/app.js
login
login.php
logs
logs/
logs/error.log
manage
manager
old
phpinfo.php
private
README.md
robots.txt
search
server-status
settings
setup
sitemap.xml
static
temp
test
test/
test/index.html
tmp
tmp/
upload
uploads
uploads/
user
users
vendor
wp-admin
wp-login.php
"""


def main():
    lab = os.path.join(ROOT, "lab")
    wl_dir = os.path.join(ROOT, "wordlists")
    os.makedirs(wl_dir, exist_ok=True)

    made = 0
    for rel, content in LAB_FILES.items():
        path = os.path.join(lab, rel.rstrip("/").replace("/", os.sep))
        if rel.endswith("/"):
            os.makedirs(path, exist_ok=True)
            made += 1
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        made += 1

    wl_path = os.path.join(wl_dir, "common.txt")
    with open(wl_path, "w", encoding="utf-8") as f:
        f.write(WORDLIST)

    n_words = len([l for l in WORDLIST.splitlines() if l.strip()])
    print(f"lab files created : {made}")
    print(f"lab dir           : {lab}")
    print(f"wordlist          : {wl_path} ({n_words} lines)")
    print()
    print("start the local test server with:")
    print(f'  .\\.venv\\Scripts\\python.exe -m http.server 8080 --directory lab')


if __name__ == "__main__":
    main()
