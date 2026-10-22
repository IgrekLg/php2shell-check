#!/usr/bin/env bash
#
# php2shell-compromise-check.sh — Проверка сервера на признаки компрометации через PHP2Shell
#
# Проверяет:
#   1. Сессионные файлы с PHP-кодом
#   2. Подозрительные файлы в /tmp
#   3. Webshell'ы в веб-каталогах
#   4. Подозрительные cron-задачи
#   5. Подозрительные процессы
#   6. Подозрительные записи в crontab
#   7. Неавторизованные SSH-ключи
#   8. Подозрительные systemd-юниты
#   9. Подозрительные сетевые соединения
#  10. Подозрительные записи в логах
#
# Usage:
#   sudo bash check_compromise.sh
#   sudo bash check_compromise.sh --output results.txt
#   sudo bash check_compromise.sh --webroot /var/www --session-dir /var/lib/php/sessions
#

set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Конфигурация ───────────────────────────────────────────────────
WEBROOTS=("/var/www" "/var/www/html" "/srv/www" "/usr/share/nginx/html" "/var/www/html" "/var/www")
SESSION_DIRS=("/var/lib/php/sessions" "/var/lib/php/session" "/tmp" "/var/tmp")
LOG_DIRS=("/var/log" "/var/log/nginx" "/var/log/apache2" "/var/log/httpd")
OUTPUT_FILE=""
VERBOSE=0
CHECKS_RUN=0
CRITICAL_FINDINGS=0
WARNING_FINDINGS=0

# ── Аргументы ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --webroot|-w)
            WEBROOTS=("$2")
            shift 2
            ;;
        --session-dir|-s)
            SESSION_DIRS=("$2")
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash $0 [options]"
            echo ""
            echo "Options:"
            echo "  --output, -o FILE    Save results to file"
            echo "  --webroot, -w DIR    Web root directory (default: common paths)"
            echo "  --session-dir, -s DIR Session directory (default: common paths)"
            echo "  --verbose, -v        Verbose output"
            echo "  --help, -h           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Утилиты ────────────────────────────────────────────────────────

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
    CHECKS_RUN=$((CHECKS_RUN + 1))
    [[ $VERBOSE -eq 1 ]] && echo "  $2"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    WARNING_FINDINGS=$((WARNING_FINDINGS + 1))
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}════════════════════════════════════════════════════════════════════${NC}"
}

# ── Проверка 1: Сессионные файлы с PHP-кодом ──────────────────────

check_session_files() {
    log_section "🔍 Проверка сессионных файлов на PHP-код"

    for sess_dir in "${SESSION_DIRS[@]}"; do
        if [[ ! -d "$sess_dir" ]]; then
            [[ $VERBOSE -eq 1 ]] && echo "  Пропуск: $sess_dir не существует"
            continue
        fi

        log_info "Проверяю $sess_dir..."

        # Ищем файлы, содержащие PHP-теги
        local php_sessions
        php_sessions=$(grep -rl '<?php\|<?=\|<?php\s\|eval(\|system(\|passthru(\|exec(\|shell_exec(\|base64_decode(\|assert(' \
            "$sess_dir"/sess_* 2>/dev/null || true)

        if [[ -n "$php_sessions" ]]; then
            log_critical "НАЙДЕНЫ сессионные файлы с PHP-кодом!"
            echo "$php_sessions" | while read -r f; do
                echo -e "  ${RED}→ $f${NC}"
                echo -e "  ${YELLOW}  Содержимое:${NC}"
                head -c 500 "$f" 2>/dev/null | grep -oE '<?[^>]+>' | head -5 | sed 's/^/    /'
            done
        else
            log_ok "Сессионные файлы чистые в $sess_dir"
        fi

        # Ищем сессионные файлы с подозрительными паттернами
        local suspicious_sessions
        suspicious_sessions=$(grep -rl 'PHP_SESSION_UPLOAD_PROGRESS\|O:\d\+:"[A-Za-z]' \
            "$sess_dir"/sess_* 2>/dev/null || true)

        if [[ -n "$suspicious_sessions" ]]; then
            log_warning "Найдены сессионные файлы с паттернами PHP2Shell:"
            echo "$suspicious_sessions" | while read -r f; do
                echo -e "  ${YELLOW}→ $f${NC}"
            done
        fi

        # Проверяем время создания сессионных файлов
        local recent_sessions
        recent_sessions=$(find "$sess_dir" -name "sess_*" -mmin -60 2>/dev/null | wc -l || echo "0")
        if [[ "$recent_sessions" -gt 100 ]]; then
            log_warning "Обнаружено $recent_sessions сессионных файлов за последние 60 минут (возможная атака)"
        fi
    done
}

# ── Проверка 2: Подозрительные файлы в /tmp ───────────────────────

check_tmp_files() {
    log_section "🔍 Проверка /tmp на подозрительные файлы"

    if [[ ! -d "/tmp" ]]; then
        log_info "/tmp не существует"
        return
    fi

    # PHP-файлы в /tmp
    local php_files
    php_files=$(find /tmp -name "*.php" -o -name "*.php[3456789]" -o -name "*.phtml" -o -name "*.phar" 2>/dev/null | head -20 || true)

    if [[ -n "$php_files" ]]; then
        log_critical "НАЙДЕНЫ PHP-файлы в /tmp!"
        echo "$php_files" | while read -r f; do
            echo -e "  ${RED}→ $f${NC}"
            ls -la "$f" 2>/dev/null | sed 's/^/    /'
        done
    else
        log_ok "PHP-файлы не найдены в /tmp"
    fi

    # Скомпилированные PHP-файлы (опкод)
    local compiled_files
    compiled_files=$(find /tmp -name "*.opcache" -o -name "*.cache" -o -name "*.zend" 2>/dev/null | head -20 || true)

    if [[ -n "$compiled_files" ]]; then
        log_warning "Найдены скомпилированные PHP-файлы в /tmp:"
        echo "$compiled_files" | while read -r f; do
            echo -e "  ${YELLOW}→ $f${NC}"
        done
    fi

    # Подозрительные исполняемые файлы
    local suspicious_binaries
    suspicious_binaries=$(find /tmp -type f -executable ! -name "sess_*" ! -name "*.log" ! -name "*.tmp" ! -name "*.pid" 2>/dev/null | head -20 || true)

    if [[ -n "$suspicious_binaries" ]]; then
        log_warning "Найдены исполняемые файлы в /tmp:"
        echo "$suspicious_binaries" | while read -r f; do
            echo -e "  ${YELLOW}→ $f${NC}"
            file "$f" 2>/dev/null | sed 's/^/    /'
        done
    fi
}

# ── Проверка 3: Webshell'ы в веб-каталогах ────────────────────────

check_webshells() {
    log_section "🔍 Проверка веб-каталогов на webshell'ы"

    for webroot in "${WEBROOTS[@]}"; do
        if [[ ! -d "$webroot" ]]; then
            [[ $VERBOSE -eq 1 ]] && echo "  Пропуск: $webroot не существует"
            continue
        fi

        log_info "Проверяю $webroot..."

        # Подозрительные имена файлов
        local suspicious_names
        suspicious_names=$(find "$webroot" -type f \( \
            -name "shell.php" -o -name "cmd.php" -o -name "c99.php" -o -name "r57.php" -o \
            -name "webshell.php" -o -name "backdoor.php" -o -name "b374k.php" -o -o \
            -name "alfa.php" -o -name "wso.php" -o -name "joomla.php" -o -o \
            -name "cpanel.php" -o -name "admin.php" -o -name "login.php" \
        \) 2>/dev/null | head -20 || true)

        if [[ -n "$suspicious_names" ]]; then
            log_critical "НАЙДЕНЫ подозрительные файлы!"
            echo "$suspicious_names" | while read -r f; do
                echo -e "  ${RED}→ $f${NC}"
            done
        fi

        # PHP-файлы с опасными функциями
        local dangerous_php
        dangerous_php=$(grep -rl 'eval(\|base64_decode(\|assert(\|system(\|passthru(\|exec(\|shell_exec(\|popen(\|proc_open(\|pcntl_exec(' \
            "$webroot"/*.php 2>/dev/null | head -20 || true)

        if [[ -n "$dangerous_php" ]]; then
            log_warning "Найдены PHP-файлы с опасными функциями:"
            echo "$dangerous_php" | while read -r f; do
                echo -e "  ${YELLOW}→ $f${NC}"
                grep -n 'eval(\|base64_decode(\|assert(\|system(\|passthru(\|exec(\|shell_exec(\|popen(\|proc_open(\|pcntl_exec(' \
                    "$f" 2>/dev/null | head -3 | sed 's/^/    /'
            done
        fi

        # PHP-файлы с подозрительными функциями (обфускация)
        local obfuscated_php
        obfuscated_php=$(grep -rl 'gzinflate(\|gzuncompress(\|str_rot13(\|base64_decode.*base64_decode\|eval.*gzinflate' \
            "$webroot"/*.php 2>/dev/null | head -20 || true)

        if [[ -n "$obfuscated_php" ]]; then
            log_warning "Найдены PHP-файлы с возможной обфускацией:"
            echo "$obfuscated_php" | while read -r f; do
                echo -e "  ${YELLOW}→ $f${NC}"
            done
        fi

        # Файлы, изменённые за последние 24 часа (кроме кэша/логов)
        local recently_modified
        recently_modified=$(find "$webroot" -type f -name "*.php" -mtime -1 ! -path "*/cache/*" ! -path "*/logs/*" ! -path "*/vendor/*" 2>/dev/null | head -20 || true)

        if [[ -n "$recently_modified" ]]; then
            log_info "PHP-файлы, изменённые за последние 24 часа:"
            echo "$recently_modified" | while read -r f; do
                echo -e "  ${CYAN}→ $f${NC}"
            done
        fi
    done
}

# ── Проверка 4: Подозрительные cron-задачи ─────────────────────────

check_cron() {
    log_section "🔍 Проверка cron-задач"

    # Системные cron-задачи
    local system_cron
    if [[ -d "/etc/cron.d" ]]; then
        system_cron=$(find /etc/cron.d -type f 2>/dev/null | head -20 || true)
        if [[ -n "$system_cron" ]]; then
            log_info "Системные cron-задачи:"
            for f in $system_cron; do
                echo -e "  ${CYAN}→ $f${NC}"
                grep -v '^#\|^$' "$f" 2>/dev/null | head -5 | sed 's/^/    /'
            done
        fi
    fi

    # Cron для текущего пользователя
    local user_cron
    user_cron=$(crontab -l 2>/dev/null || true)
    if [[ -n "$user_cron" ]]; then
        log_info "Crontab текущего пользователя:"
        echo "$user_cron" | grep -v '^#\|^$' | head -20 | sed 's/^/    /'

        # Проверяем на подозрительные команды
        if echo "$user_cron" | grep -qE 'curl.*\|.*sh|wget.*\|.*bash|nc.*-e|ncat.*-e|bash.*-i|python.*-c.*import|php.*-r.*eval|perl.*-e.*exec'; then
            log_critical "НАЙДЕНЫ подозрительные cron-задачи!"
            echo "$user_cron" | grep -E 'curl.*\|.*sh|wget.*\|.*bash|nc.*-e|ncat.*-e|bash.*-i|python.*-c.*import|php.*-r.*eval|perl.*-e.*exec' | sed 's/^/    /'
        fi
    fi

    # Анонимные cron-задачи
    if [[ -f "/etc/crontab" ]]; then
        log_info "Системный crontab:"
        grep -v '^#\|^$' /etc/crontab 2>/dev/null | head -20 | sed 's/^/    /'
    fi
}

# ── Проверка 5: Подозрительные процессы ────────────────────────────

check_processes() {
    log_section "🔍 Проверка процессов"

    # PHP-процессы
    local php_procs
    php_procs=$(ps aux | grep -E 'php|httpd|apache|nginx' | grep -v grep | head -20 || true)

    if [[ -n "$php_procs" ]]; then
        log_info "PHP-процессы:"
        echo "$php_procs" | while read -r line; do
            echo -e "  ${CYAN}→ $line${NC}"
        done
    fi

    # Подозрительные процессы (обратные shell'ы)
    local suspicious_procs
    suspicious_procs=$(ps aux | grep -E 'nc -[elp]|ncat|socat|bash -i|python.*-c.*socket|perl.*-e.*socket|ruby.*-e.*socket' | grep -v grep || true)

    if [[ -n "$suspicious_procs" ]]; then
        log_critical "НАЙДЕНЫ подозрительные процессы (возможные reverse shell)!"
        echo "$suspicious_procs" | sed 's/^/    /'
    fi

    # Процессы с подозрительными аргументами
    local weird_procs
    weird_procs=$(ps aux | grep -E '/dev/tcp|/dev/udp|/proc/self|/dev/shm' | grep -v grep || true)

    if [[ -n "$weird_procs" ]]; then
        log_critical "НАЙДЕНЫ процессы с подозрительными аргументами!"
        echo "$weird_procs" | sed 's/^/    /'
    fi
}

# ── Проверка 6: SSH-ключи ─────────────────────────────────────────

check_ssh_keys() {
    log_section "🔍 Проверка SSH-ключей"

    # Проверяем authorized_keys для всех пользователей
    local users
    users=$(cut -d: -f1 /etc/passwd 2>/dev/null | grep -vE 'nologin|false|sync|shutdown|halt' || true)

    for user in $users; do
        local home
        home=$(eval echo "~$user" 2>/dev/null || echo "")
        [[ -z "$home" ]] && continue

        local auth_keys="$home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            log_info "authorized_keys для $user:"
            local key_count
            key_count=$(wc -l < "$auth_keys" 2>/dev/null || echo "0")
            echo -e "  ${CYAN}→ $key_count ключей${NC}"

            # Проверяем на неизвестные ключи
            if [[ "$key_count" -gt 3 ]]; then
                log_warning "Много SSH-ключей для $user ($key_count) — проверьте!"
            fi
        fi
    done

    # Проверяем known_hosts на подозрительные хосты
    local known_hosts
    known_hosts=$(find /root /home -name "known_hosts" 2>/dev/null | head -5 || true)

    if [[ -n "$known_hosts" ]]; then
        log_info "Файлы known_hosts:"
        for f in $known_hosts; do
            echo -e "  ${CYAN}→ $f${NC}"
        done
    fi
}

# ── Проверка 7: Подозрительные systemd-юниты ──────────────────────

check_systemd() {
    log_section "🔍 Проверка systemd-юнитов"

    # Подозрительные юниты
    local suspicious_units
    suspicious_units=$(systemctl list-units --all --no-pager 2>/dev/null | grep -iE 'tmp|shell|backdoor|reverse|ncat|socat|python|perl' || true)

    if [[ -n "$suspicious_units" ]]; then
        log_critical "НАЙДЕНЫ подозрительные systemd-юниты!"
        echo "$suspicious_units" | sed 's/^/    /'
    fi

    # Юниты в /tmp
    local tmp_units
    tmp_units=$(find /tmp -name "*.service" -o -name "*.timer" 2>/dev/null | head -10 || true)

    if [[ -n "$tmp_units" ]]; then
        log_critical "НАЙДЕНЫ systemd-юниты в /tmp!"
        echo "$tmp_units" | sed 's/^/    /'
    fi
}

# ── Проверка 8: Сетевые соединения ─────────────────────────────────

check_network() {
    log_section "🔍 Проверка сетевых соединений"

    # Активные соединения
    local connections
    connections=$(ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true)

    if [[ -n "$connections" ]]; then
        log_info "Активные TCP-соединения:"
        echo "$connections" | grep -E 'ESTAB|LISTEN' | head -30 | sed 's/^/    /'

        # Подозрительные соединения (внешние на нестандартные порты)
        local suspicious_conns
        suspicious_conns=$(echo "$connections" | grep -E 'ESTAB.*:(4444|5555|6666|7777|8888|9999|1234|31337|12345|54321)' || true)

        if [[ -n "$suspicious_conns" ]]; then
            log_critical "НАЙДЕНЫ подозрительные соединения!"
            echo "$suspicious_conns" | sed 's/^/    /'
        fi
    fi

    # Подозрительные порты
    local listening_ports
    listening_ports=$(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true)

    if [[ -n "$listening_ports" ]]; then
        log_info "Прослушиваемые порты:"
        echo "$listening_ports" | grep LISTEN | head -20 | sed 's/^/    /'
    fi
}

# ── Проверка 9: Логи ──────────────────────────────────────────────

check_logs() {
    log_section "🔍 Проверка логов"

    for log_dir in "${LOG_DIRS[@]}"; do
        if [[ ! -d "$log_dir" ]]; then
            continue
        fi

        log_info "Проверяю $log_dir..."

        # PHP-ошибки с upload_progress
        local php_errors
        php_errors=$(grep -rl 'PHP_SESSION_UPLOAD_PROGRESS\|upload_progress\|Session ID.*illegal' \
            "$log_dir"/*.log 2>/dev/null | head -10 || true)

        if [[ -n "$php_errors" ]]; then
            log_warning "Найдены ошибки upload_progress в логах:"
            for f in $php_errors; do
                echo -e "  ${YELLOW}→ $f${NC}"
                tail -5 "$f" 2>/dev/null | grep -i 'upload_progress\|session.*illegal' | sed 's/^/    /'
            done
        fi

        # Подозрительные запросы в access-логах
        local suspicious_requests
        suspicious_requests=$(grep -rl 'PHP_SESSION_UPLOAD_PROGRESS' \
            "$log_dir"/*access*.log 2>/dev/null | head -10 || true)

        if [[ -n "$suspicious_requests" ]]; then
            log_warning "Подозрительные запросы с PHP_SESSION_UPLOAD_PROGRESS:"
            for f in $suspicious_requests; do
                echo -e "  ${YELLOW}→ $f${NC}"
                grep 'PHP_SESSION_UPLOAD_PROGRESS' "$f" 2>/dev/null | tail -3 | sed 's/^/    /'
            done
        fi

        # Логи с ошибками сессий
        local session_errors
        session_errors=$(grep -rl 'Failed to read session data\|Session object destruction failed' \
            "$log_dir"/*.log 2>/dev/null | head -10 || true)

        if [[ -n "$session_errors" ]]; then
            log_warning "Найдены ошибки сессий в логах:"
            for f in $session_errors; do
                echo -e "  ${YELLOW}→ $f${NC}"
                tail -3 "$f" 2>/dev/null | grep -i 'session' | sed 's/^/    /'
            done
        fi
    done
}

# ── Проверка 10: Права доступа ─────────────────────────────────────

check_permissions() {
    log_section "🔍 Проверка прав доступа"

    # Мировые файлы с записью в веб-каталогах
    for webroot in "${WEBROOTS[@]}"; do
        if [[ ! -d "$webroot" ]]; then
            continue
        fi

        log_info "Проверяю права в $webroot..."

        # Файлы, доступные для записи всем
        local world_writable
        world_writable=$(find "$webroot" -type f -perm -o+w 2>/dev/null | head -20 || true)

        if [[ -n "$world_writable" ]]; then
            log_warning "Мировые файлы с записью в $webroot:"
            echo "$world_writable" | head -10 | while read -r f; do
                echo -e "  ${YELLOW}→ $f${NC}"
            done
        fi

        # PHP-файлы, доступные для записи всем
        local world_writable_php
        world_writable_php=$(find "$webroot" -type f -name "*.php" -perm -o+w 2>/dev/null | head -20 || true)

        if [[ -n "$world_writable_php" ]]; then
            log_critical "Мировые PHP-файлы с записью в $webroot!"
            echo "$world_writable_php" | head -10 | while read -r f; do
                echo -e "  ${RED}→ $f${NC}"
            done
        fi
    done
}

# ── Проверка 11: PHP-конфигурация ─────────────────────────────────

check_php_config() {
    log_section "🔍 Проверка PHP-конфигурации"

    # Находим php.ini
    local php_ini
    php_ini=$(php -i 2>/dev/null | grep 'Loaded Configuration File' | awk '{print $NF}' || true)

    if [[ -z "$php_ini" ]]; then
        log_info "php.ini не найден (возможно, PHP не установлен)"
        return
    fi

    log_info "PHP-конфиг: $php_ini"

    # Проверяем upload_progress
    local upload_progress_enabled
    upload_progress_enabled=$(grep -E '^\s*session\.upload_progress\.enabled' "$php_ini" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$upload_progress_enabled" == "On" || -z "$upload_progress_enabled" ]]; then
        log_warning "session.upload_progress.enabled = On (по умолчанию) — уязвимо к CVE-2026-109618"
    fi

    # Проверяем upload_progress cleanup
    local upload_progress_cleanup
    upload_progress_cleanup=$(grep -E '^\s*session\.upload_progress\.cleanup' "$php_ini" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$upload_progress_cleanup" == "Off" ]]; then
        log_critical "session.upload_progress.cleanup = Off — критично уязвимо к PHP2Shell!"
    fi

    # Проверяем display_errors
    local display_errors
    display_errors=$(grep -E '^\s*display_errors' "$php_ini" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$display_errors" == "On" ]]; then
        log_warning "display_errors = On — атака может быть обнаружена по ошибкам PHP"
    fi

    # Проверяем session.use_strict_mode
    local strict_mode
    strict_mode=$(grep -E '^\s*session\.use_strict_mode' "$php_ini" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$strict_mode" != "On" ]]; then
        log_warning "session.use_strict_mode != On — уязвимо к session fixation"
    fi

    # Проверяем PHP-версию
    local php_version
    php_version=$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)

    if [[ -n "$php_version" ]]; then
        log_info "Версия PHP: $php_version"

        # Проверяем на уязвимые версии
        if echo "$php_version" | grep -qE '^5\.'; then
            log_critical "PHP 5.x — EOL, критически уязвимо!"
        elif echo "$php_version" | grep -qE '^7\.'; then
            log_critical "PHP 7.x — EOL, критически уязвимо!"
        elif echo "$php_version" | grep -qE '^8\.0\.'; then
            log_critical "PHP 8.0.x — EOL, критически уязвимо!"
        elif echo "$php_version" | grep -qE '^8\.1\.'; then
            log_critical "PHP 8.1.x — EOL, критически уязвимо!"
        fi
    fi
}

# ── Итоговая сводка ────────────────────────────────────────────────

print_summary() {
    log_section "📊 ИТОГОВАЯ СВОДКА"

    echo ""
    echo -e "  ${BOLD}Проверок выполнено:${NC}    $CHECKS_RUN"
    echo -e "  ${RED}Критических находок:${NC}   $CRITICAL_FINDINGS"
    echo -e "  ${YELLOW}Предупреждений:${NC}        $WARNING_FINDINGS"
    echo ""

    if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
        echo -e "  ${RED}⚠️  ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ПРИЗНАКИ КОМПРОМЕТАЦИИ!${NC}"
        echo ""
        echo "  НЕМЕДЛЕННО:"
        echo "  1. Отключите сайт от сети"
        echo "  2. Сделайте дамп памяти (dd if=/dev/mem of=/tmp/memdump.img)"
        echo "  3. Сохраните логи и сессионные файлы"
        echo "  4. Обратитесь к специалистам по инцидентам"
        echo "  5. Восстановите из чистой резервной копии"
        echo ""
    elif [[ $WARNING_FINDINGS -gt 0 ]]; then
        echo -e "  ${YELLOW}⚠️  ОБНАРУЖЕНЫ ПОДОЗРИТЕЛЬНЫЕ АНОМАЛИИ.${NC}"
        echo ""
        echo "  РЕКОМЕНДУЕТСЯ:"
        echo "  1. Проверить все критические находки вручную"
        echo "  2. Обновить PHP до последней версии"
        echo "  3. Отключить session.upload_progress.enabled"
        echo "  4. Проверить все файлы на наличие webshell'ов"
        echo "  5. Сменить все пароли"
        echo ""
    else
        echo -e "  ${GREEN}✅ Сервер чист. Критических находок не обнаружено.${NC}"
        echo ""
        echo "  РЕКОМЕНДАЦИИ:"
        echo "  1. Обновите PHP до последней версии"
        echo "  2. Отключите session.upload_progress.enabled"
        echo "  3. Включите session.use_strict_mode"
        echo "  4. Настройте мониторинг логов"
        echo "  5. Запускайте проверку регулярно"
        echo ""
    fi

    echo -e "  ${BOLD}════════════════════════════════════════════════════════════════════${NC}"
}

# ── Основная функция ──────────────────────────────────────────────

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  PHP2Shell Compromise Check — Проверка на компрометацию        ║${NC}"
    echo -e "${BOLD}║  CVE-2026-109618 / CVE-2026-109619                             ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Запуск:${NC} sudo bash $0"
    echo -e "  ${CYAN}Дата:${NC}  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo -e "  ${CYAN}Хост:${NC}  $(hostname 2>/dev/null || echo 'unknown')"
    echo -e "  ${CYAN}Ядро:${NC}  $(uname -r 2>/dev/null || echo 'unknown')"
    echo ""

    # Запускаем все проверки
    check_php_config
    check_session_files
    check_tmp_files
    check_webshells
    check_cron
    check_processes
    check_ssh_keys
    check_systemd
    check_network
    check_logs
    check_permissions

    # Итоговая сводка
    print_summary

    # Если есть output-файл, дублируем в него
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "Результаты сохранены в: $OUTPUT_FILE"
    fi
}

# Запуск
main
