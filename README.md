# php2shell-check — Безопасная проверка PHP на уязвимость CVE-2026-109618 / CVE-2026-109619

> 🔒 **Безопасный сканер** — проверяет уязвимость PHP-сайтов к PHP2Shell без запуска эксплойтов. Только косвенные detection-проверки.

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![CVE-2026-109618](https://img.shields.io/badge/CVE--2026--109618-critical-red)](https://cve.mitre.org/)
[![CVE-2026-109619](https://img.shields.io/badge/CVE--2026--109619-critical-red)](https://cve.mitre.org/)
[![No dependencies](https://img.shields.io/badge/dependencies-stdlib-brightgreen)](https://docs.python.org/3/library/index.html)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Содержание

- [Что такое PHP2Shell?](#что-такое-php2shell)
- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [5 проверок](#5-проверок)
- [Примеры использования](#примеры-использования)
- [Результаты проверки ваших сайтов](#результаты-проверки-ваших-сайтов)
- [Сравнение с другими инструментами](#сравнение-с-другими-инструментами)
- [Митигация](#митигация)
- [Дисклеймер](#дисклеймер)

---

## Что такое PHP2Shell?

**PHP2Shell** — цепочка критических уязвимостей в PHP-ядре (CVSS 9.2), позволяющая получить RCE без аутентификации:

| CVE | Описание | Затронутые версии | Исправлено в |
|-----|----------|-------------------|--------------|
| **CVE-2026-109618** | Session upload_progress UAF/OOM | PHP 5.4.0 – 8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| **CVE-2026-109619** | `var_destroy` use-after-free через `unserialize()` | PHP 5.4.0 – 8.5.11 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

**Атакующий цепочка:**
```
Session fixation через upload_progress
        │
        ▼
  Session file injection (PHP-код в filename)
        │
        ▼
  Local File Inclusion (LFI) сессионного файла
        │
        ▼
         RCE ← PHP-код в сессии выполняется сервером
```

---

## Возможности

- ✅ **5 проверок** в одном скрипте
- ✅ **Zero dependencies** — только Python stdlib
- ✅ **Безопасный** — только detection, без payload'ов RCE
- ✅ **Цветной вывод** для быстрой оценки
- ✅ **JSON-вывод** для CI/CD и SIEM
- ✅ **Пакетная проверка** из файла URL'ов
- ✅ **Настраиваемый таймаут**

---

## Быстрый старт

```bash
# Скачайте скрипт
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/php2shell-check/main/check_php2shell.py

# Проверка одного сайта
python3 check_php2shell.py https://example.com

# Проверка из файла
python3 check_php2shell.py --file urls.txt

# JSON-вывод для CI/CD
python3 check_php2shell.py https://example.com --json > results.json
```

**Требования:** Python 3.6+, никаких сторонних пакетов.

---

## 5 проверок

| # | Проверка | Что проверяет | Когда срабатывает |
|---|----------|---------------|-------------------|
| 1 | **CVE-2026-109619** | Версия PHP через `X-Powered-By` | PHP-версия в уязвимом диапазоне |
| 2 | **CVE-2026-109618** | UAF/OOM через upload_progress с невалидным SID | PHP выводит предупреждения о сессии |
| 3 | **upload_progress cookie** | Создание сессии при POST с `PHP_SESSION_UPLOAD_PROGRESS` | upload_progress активен |
| 4 | **Handler mismatch** | Разные `session.serialize_handler` на разных endpoint'ах | Обнаружена десериализационная путаница |
| 5 | **Session injection + LFI** | PHP-код в filename → сессия → LFI → RCE | Маркер вернулся через LFI |

---

## Примеры использования

### Базовая проверка (все 5 проверок)

```bash
python3 check_php2shell.py https://example.com
```

### Проверка с LFI-цепочкой

```bash
python3 check_php2shell.py https://example.com --lfi "/vuln.php?page="
```

### Проверка handler mismatch

```bash
python3 check_php2shell.py https://example.com \
    --handler-write /upload.php \
    --handler-read /api/data.php
```

### Полная проверка

```bash
python3 check_php2shell.py https://example.com --all \
    --lfi "/vuln.php?page=" \
    --handler-write /upload.php \
    --handler-read /api/data.php
```

### Пакетная проверка

```bash
# urls.txt:
# https://site1.com
# https://site2.com
# https://site3.com
python3 check_php2shell.py --file urls.txt
```

### JSON-вывод

```bash
python3 check_php2shell.py https://example.com --json
```




## Сравнение с другими инструментами

| Фича | php2shell-check | php2shell-poc | php2shellbt |
|------|-----------------|---------------|-------------|
| Версия PHP | ✅ | ✅ | ✅ |
| CVE-2026-109618 (UAF/OOM) | ✅ | ✅ | ✅ |
| upload_progress cookie | ✅ | ❌ | ❌ |
| Handler mismatch | ✅ | ✅ | ✅ |
| Session injection + LFI | ✅ | ✅ | ✅ |
| Безопасный (без RCE) | ✅ | ❌ | ❌ |
| JSON-вывод | ✅ | ❌ | ✅ |
| Пакетная проверка | ✅ | ❌ | ❌ |

---

## Митигация

### Немедленные меры:

```ini
; php.ini
session.upload_progress.enabled = Off
session.upload_progress.cleanup = On
session.use_strict_mode = On
```

### Долгосрочные меры:

1. **Обновите PHP** до патчной версии:
   - PHP 8.2.x → 8.2.35+
   - PHP 8.3.x → 8.3.36+
   - PHP 8.4.x → 8.4.27+
   - PHP 8.5.x → 8.5.12+

2. **Проверьте сервер на компрометацию:**
   ```bash
   grep -r '<?php' /tmp/sessions/
   grep -r 'PHP_SESSION_UPLOAD_PROGRESS' /tmp/sessions/
   ```

3. **Настраивайте WAF** для блокировки multipart POST с PHP-кодом в filename

---

## Дисклеймер

> ⚠️ **Этот инструмент предназначен только для авторизованного тестирования безопасности.**
>
> Использование против систем, которыми вы не владеете или не имеете явного письменного разрешения, является **незаконным** и неэтичным. Всегда получайте надлежащее разрешение перед запуском любого сканирования безопасности.
>
> Этот инструмент выполняет только **detection-проверки** и не содержит payload'ов для RCE.

---

## Ссылки

- [CVE-2026-109618](https://cve.mitre.org/) — NVD entry
- [CVE-2026-109619](https://cve.mitre.org/) — NVD entry
- [PHP session.upload_progress](https://www.php.net/manual/en/session.upload-progress.php) — документация PHP
- [OWASP LFI](https://owasp.org/www-project-web-security-testing-guide/) — Testing guide
- [php2shell-poc](https://github.com/ikow/php2shell-poc) — POC эксплойт
- [php2shellbt](https://github.com/pentestershell/php2shellbt) — аналогичный сканер

---

## License

MIT © 2026
