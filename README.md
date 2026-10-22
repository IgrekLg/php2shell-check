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
- [Проверка на компрометацию (bash)](#проверка-на-компрометацию-bash)
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

## Проверка на компрометацию (bash)
Скрипт `php2shell-compromise-check.sh` проверяет сервер на **признаки уже произошедшей атаки** через PHP2Shell.
> ⚠️ Требует `sudo` — проверяет системные файлы, логи, процессы.
### Что проверяет (11 проверок):
| # | Проверка | Что ищет |
|---|----------|----------|
| 1 | **PHP-конфиг** | `upload_progress.enabled`, `cleanup=Off`, EOL-версии PHP |
| 2 | **Сессионные файлы** | PHP-код в `sess_*`, паттерны PHP2Shell, аномальная активность |
| 3 | **/tmp** | PHP-файлы, скомпилированные файлы, исполняемые бинарники |
| 4 | **Webshell'ы** | Известные имена (c99, r57, b374k, wso), опасные функции, обфускация |
| 5 | **Cron** | Подозрительные команды (reverse shell, `curl\|sh`, `python -c socket`) |
| 6 | **Процессы** | Reverse shell'ы, `/dev/tcp`, `/dev/shm` |
| 7 | **SSH-ключи** | `authorized_keys`, `known_hosts` |
| 8 | **systemd** | Подозрительные юниты, юниты в /tmp |
| 9 | **Сеть** | Reverse shell-порты (4444, 31337, 12345, 54321) |
| 10 | **Логи** | Ошибки upload_progress, подозрительные запросы |
| 11 | **Права** | Мировые PHP-файлы с записью |
### Быстрый старт
```bash
# Скачайте скрипт
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/php2shell-check/main/php2shell-compromise-check.sh
chmod +x php2shell-compromise-check.sh
# Базовая проверка
sudo bash php2shell-compromise-check.sh
# С указанием веб-каталога
sudo bash php2shell-compromise-check.sh --webroot /var/www/html
# С указанием директории сессий
sudo bash php2shell-compromise-check.sh --session-dir /var/lib/php/sessions
# Вывод в файл
sudo bash php2shell-compromise-check.sh --output results.txt
# Подробный режим
sudo bash php2shell-compromise-check.sh --verbose
```
### Пример вывода
```
════════════════════════════════════════════════════════════════════
  🔍 Проверка сессионных файлов на PHP-код
════════════════════════════════════════════════════════════════════
[INFO] Проверяю /var/lib/php/sessions...
[CRITICAL] НАЙДЕНЫ сессионные файлы с PHP-кодом!
  → /var/lib/php/sessions/sess_abc123
    Содержимое:
    <?php echo 'NUCLEI...'; ?>
════════════════════════════════════════════════════════════════════
  📊 ИТОГОВАЯ СВОДКА
════════════════════════════════════════════════════════════════════
  Проверок выполнено:    11
  Критических находок:   3
  Предупреждений:        5
  ⚠️ ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ПРИЗНАКИ КОМПРОМЕТАЦИИ!
  НЕМЕДЛЕННО:
  1. Отключите сайт от сети
  2. Сделайте дамп памяти (dd if=/dev/mem of=/tmp/memdump.img)
  3. Сохраните логи и сессионные файлы
  4. Обратитесь к специалистам по инцидентам
  5. Восстановите из чистой резервной копии
```
### Как интерпретировать результаты
| Статус | Что означает |
|--------|--------------|
| 🟢 **Сервер чист** | Критических находок нет, но обновите PHP и отключите `upload_progress` |
| 🟡 **Подозрительные аномалии** | Проверьте вручную, обновите PHP, смените пароли |
| 🔴 **Критические признаки** | Сервер скомпрометирован — отключайте от сети, вызывайте специалистов |
### Когда запускать
- **Сразу после** обнаружения уязвимости через `check_php2shell.py`
- **Регулярно** как часть мониторинга (cron, CI/CD)
- **При подозрении** на компрометацию (странные процессы, высокая нагрузка)
- **После обновления** PHP — чтобы убедиться, что атака не была до обновления
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
