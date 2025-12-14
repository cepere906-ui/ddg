#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDN DDoS Protection v2 - Maximum Protection Edition
====================================================
Многоуровневая адаптивная защита:
1. Kernel hardening (sysctl)
2. Iptables/nftables DDoS filters
3. Nginx adaptive rate limiting
4. Real-time attack detection
5. Auto-escalation to "war mode"
"""

import os
import sys
import signal
import subprocess
import shutil
import time
import threading
import re
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass
from datetime import datetime
import atexit

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

TARGET_DOMAIN = "daytepizdipz.hiend.shop"
ORIGIN_IP     = "94.159.100.238"
ORIGIN_PORT   = 443

# Режимы защиты
@dataclass
class ProtectionMode:
    name: str
    req_rate: str          # requests/sec
    req_burst: int         # burst size
    conn_limit: int        # connections per IP
    iptables_new_limit: str # iptables new conn limit

MODES = {
    'NORMAL': ProtectionMode('NORMAL', '30r/s', 50, 100, '50/sec'),
    'ALERT':  ProtectionMode('ALERT',  '15r/s', 30, 50,  '30/sec'),
    'WAR':    ProtectionMode('WAR',    '5r/s',  10, 20,  '10/sec')
}

ATTACK_DETECTION_THRESHOLD = 1000  # req/sec для включения ALERT
WAR_MODE_THRESHOLD = 5000          # req/sec для включения WAR

# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'

class CDNDDoSProtection:
    def __init__(self, domain: str, origin_ip: str, origin_port: int = 443):
        self.domain = domain
        self.origin_ip = origin_ip
        self.origin_port = origin_port
        self.origin_proto = "https" if origin_port == 443 else "http"
        
        # Пути
        self.nginx_site_config = f"/etc/nginx/sites-available/{domain}"
        self.nginx_site_enabled = f"/etc/nginx/sites-enabled/{domain}"
        self.nginx_main_backup = "/etc/nginx/nginx.conf.backup"
        self.sysctl_config = "/etc/sysctl.d/99-ddos-protection.conf"
        self.ssl_cert = "/etc/ssl/certs/nginx-selfsigned.crt"
        self.ssl_key = "/etc/ssl/private/nginx-selfsigned.key"
        self.iptables_rules_file = "/tmp/ddos_iptables.rules"
        
        # Состояние
        self.current_mode = 'NORMAL'
        self.created_files: List[str] = []
        self.created_symlinks: List[str] = []
        self.iptables_initialized = False
        self.nginx_was_installed = self._check_nginx_installed()
        
        # Мониторинг
        self.monitoring = True
        self.monitor_thread = None
        
        # Хуки для очистки
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        atexit.register(self.cleanup)
        
    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Завершение...{Colors.NC}")
        self.monitoring = False
        sys.exit(0)
    
    def _check_nginx_installed(self) -> bool:
        return shutil.which('nginx') is not None
    
    def _run_command(self, cmd: str, shell: bool = True, check: bool = True) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(cmd, shell=shell, check=check, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            if check:
                print(f"{Colors.RED}✗ Ошибка: {cmd}{Colors.NC}")
                if e.stderr:
                    print(f"{Colors.RED}  {e.stderr[:200]}{Colors.NC}")
            raise
    
    def _print_step(self, message: str):
        print(f"\n{Colors.CYAN}▶ {message}{Colors.NC}")
    
    def install_dependencies(self):
        """Установка всех зависимостей"""
        if self.nginx_was_installed:
            return
        
        self._print_step("Установка зависимостей...")
        
        if Path("/etc/debian_version").exists():
            self._run_command("apt-get update -qq", check=False)
            pkgs = "nginx iptables ipset openssl net-tools"
            self._run_command(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs} > /dev/null 2>&1")
        elif Path("/etc/redhat-release").exists():
            self._run_command("yum install -y epel-release > /dev/null 2>&1", check=False)
            pkgs = "nginx iptables ipset openssl net-tools"
            self._run_command(f"yum install -y {pkgs} > /dev/null 2>&1")
        
        print(f"{Colors.GREEN}✓ Зависимости установлены{Colors.NC}")
    
    def configure_kernel_hardening(self):
        """Максимальное ужесточение kernel параметров для DDoS защиты"""
        self._print_step("Ужесточение ядра (MAXIMUM SECURITY)...")
        
        sysctl_config = """# === MAXIMUM DDoS PROTECTION KERNEL HARDENING ===

# === CORE NETWORKING ===
net.core.netdev_max_backlog = 65536
net.core.rmem_default = 262144
net.core.rmem_max = 67108864
net.core.wmem_default = 262144
net.core.wmem_max = 67108864
net.core.somaxconn = 65535
net.core.optmem_max = 25165824

# === TCP HARDENING ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr

# === IP SECURITY ===
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === CONNECTION TRACKING ===
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# === IPv6 HARDENING ===
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.forwarding = 0

# === ARP PROTECTION ===
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.neigh.default.gc_stale_time = 120

# === FILE DESCRIPTORS ===
fs.file-max = 2097152
fs.nr_open = 2097152

# === MEMORY ===
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 10
vm.min_free_kbytes = 65536
vm.overcommit_memory = 1

# === KERNEL SECURITY ===
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.panic = 10
kernel.pid_max = 4194304
"""
        
        with open(self.sysctl_config, "w") as f:
            f.write(sysctl_config)
        self.created_files.append(self.sysctl_config)
        
        result = self._run_command(f"sysctl -p {self.sysctl_config} 2>&1", check=False)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓ Kernel hardened to maximum{Colors.NC}")
        else:
            print(f"{Colors.YELLOW}⚠ Некоторые параметры недоступны (WSL/container){Colors.NC}")
    
    def setup_iptables_ddos_protection(self):
        """Настройка многоуровневой iptables защиты"""
        self._print_step("Настройка iptables DDoS фильтров...")
        
        # Проверяем доступность iptables
        if not shutil.which('iptables'):
            print(f"{Colors.YELLOW}⚠ iptables недоступен{Colors.NC}")
            return
        
        # Очищаем старые правила
        self._run_command("iptables -F", check=False)
        self._run_command("iptables -X", check=False)
        self._run_command("iptables -t mangle -F", check=False)
        self._run_command("iptables -t mangle -X", check=False)
        self._run_command("iptables -t raw -F", check=False)
        self._run_command("iptables -t raw -X", check=False)
        
        rules = [
            # === RAW TABLE (самая ранняя точка) ===
            # Блокируем invalid пакеты
            "iptables -t raw -A PREROUTING -m conntrack --ctstate INVALID -j DROP",
            
            # Блокируем фрагменты (часто используются в атаках)
            "iptables -t raw -A PREROUTING -f -j DROP",
            
            # === MANGLE TABLE (до PREROUTING) ===
            # Блокируем подозрительные TCP флаги
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP",
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP",
            
            # Блокируем XMAS packets
            "iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP",
            
            # === FILTER TABLE ===
            # Loopback всегда разрешен
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            
            # Established и related соединения
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            
            # SYN flood protection - лимит новых соединений
            f"iptables -A INPUT -p tcp --syn -m limit --limit {MODES['NORMAL'].iptables_new_limit} --limit-burst 100 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
            
            # SSH защита (если используется)
            "iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set",
            "iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
            
            # HTTP/HTTPS
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            
            # Блокируем ICMP flood
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 2 -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
            
            # Лимит соединений на IP
            "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 -j REJECT",
            "iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 100 -j REJECT",
            
            # Port scanning protection
            "iptables -N port-scan-drop",
            "iptables -A port-scan-drop -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN",
            "iptables -A port-scan-drop -j DROP",
            "iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j port-scan-drop",
            
            # Default policy
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
        ]
        
        print(f"{Colors.CYAN}  Применение правил...{Colors.NC}")
        failed = 0
        for rule in rules:
            result = self._run_command(rule, check=False)
            if result.returncode != 0:
                failed += 1
        
        if failed == 0:
            print(f"{Colors.GREEN}✓ Iptables DDoS фильтры активны ({len(rules)} правил){Colors.NC}")
        else:
            print(f"{Colors.YELLOW}✓ Iptables частично активны ({len(rules)-failed}/{len(rules)} правил){Colors.NC}")
        
        self.iptables_initialized = True
    
    def update_iptables_limits(self, mode: str):
        """Обновление iptables лимитов в зависимости от режима"""
        if not self.iptables_initialized:
            return

        limit = MODES[mode].iptables_new_limit

        # Удаляем старые правила для всех режимов, чтобы не копились дубликаты
        for value in {m.iptables_new_limit for m in MODES.values()}:
            self._run_command(
                f"iptables -D INPUT -p tcp --syn -m limit --limit {value} --limit-burst 100 -j ACCEPT",
                check=False,
            )

        # Добавляем новое с обновленным лимитом
        self._run_command(f"iptables -I INPUT -p tcp --syn -m limit --limit {limit} --limit-burst 100 -j ACCEPT", check=False)

        print(f"{Colors.MAGENTA}  Iptables лимит: {limit}{Colors.NC}")
    
    def generate_ssl_cert(self):
        """Генерация self-signed сертификата"""
        self._print_step("Генерация SSL сертификата...")
        
        if os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
            print(f"{Colors.YELLOW}  Сертификат уже существует{Colors.NC}")
            return
        
        os.makedirs("/etc/ssl/private", exist_ok=True)
        
        cmd = (
            f'openssl req -x509 -nodes -days 365 -newkey rsa:2048 '
            f'-keyout {self.ssl_key} '
            f'-out {self.ssl_cert} '
            f'-subj "/C=RU/ST=Moscow/L=Moscow/O=CDN/CN={self.domain}"'
        )
        
        self._run_command(cmd)
        self.created_files.extend([self.ssl_cert, self.ssl_key])
        
        print(f"{Colors.GREEN}✓ SSL сертификат создан{Colors.NC}")
    
    def configure_nginx(self, mode: str = 'NORMAL'):
        """Конфигурация Nginx с адаптивными лимитами"""
        self._print_step(f"Конфигурация Nginx (режим: {mode})...")
        
        m = MODES[mode]
        
        # Бэкап оригинального конфига
        if os.path.exists("/etc/nginx/nginx.conf") and not os.path.exists(self.nginx_main_backup):
            shutil.copy("/etc/nginx/nginx.conf", self.nginx_main_backup)
            self.created_files.append(self.nginx_main_backup)
        
        # Оптимизированный nginx.conf
        nginx_main_conf = f"""user www-data;
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 100000;
pid /run/nginx.pid;

events {{
    worker_connections 10000;
    use epoll;
    multi_accept on;
}}

http {{
    # === BASIC ===
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 10;
    keepalive_requests 100;
    reset_timedout_connection on;
    types_hash_max_size 2048;
    server_tokens off;
    
    # === CLIENT LIMITS ===
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
    
    # === RATE LIMITING (ADAPTIVE) ===
    limit_req_zone $binary_remote_addr zone=general:20m rate={m.req_rate};
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:20m;
    
    # === LOGS ===
    log_format ddos_detect '$remote_addr - [$time_local] "$request" '
                           '$status $body_bytes_sent "$http_user_agent" '
                           '$request_time';
    access_log /var/log/nginx/access.log ddos_detect;
    error_log /var/log/nginx/error.log warn;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}}
"""
        
        with open("/etc/nginx/nginx.conf", "w") as f:
            f.write(nginx_main_conf)
        
        # Конфиг сайта
        site_conf = f"""
# === UPSTREAM ===
upstream origin_backend {{
    server {self.origin_ip}:{self.origin_port} max_fails=3 fail_timeout=30s;
    keepalive 64;
    keepalive_requests 100;
    keepalive_timeout 60s;
}}

# === GEO BLOCKING (опционально) ===
geo $blocked_country {{
    default 0;
    # CN 1;  # China
    # RU 1;  # Russia
}}

# === USER AGENT BLOCKING ===
map $http_user_agent $bad_bot {{
    default 0;
    ~*(bot|crawler|spider|scraper|curl|wget|python|java|ruby) 1;
}}

# === HTTP -> HTTPS ===
server {{
    listen 80;
    server_name {self.domain};
    
    # Health check endpoint (no SSL)
    location /health {{
        access_log off;
        return 200 "OK\\n";
        add_header Content-Type text/plain;
    }}
    
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# === HTTPS SERVER ===
server {{
    listen 443 ssl http2;
    server_name {self.domain};
    
    # === SSL CONFIG ===
    ssl_certificate {self.ssl_cert};
    ssl_certificate_key {self.ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_buffer_size 4k;
    
    # === DDOS PROTECTION (MODE: {mode}) ===
    limit_req zone=general burst={m.req_burst} nodelay;
    limit_conn conn_limit {m.conn_limit};
    
    # Блокируем пустые User-Agent
    if ($http_user_agent = "") {{
        return 444;
    }}
    
    # Блокируем ботов
    if ($bad_bot) {{
        return 403;
    }}
    
    # Блокируем страны (если включено)
    if ($blocked_country) {{
        return 403;
    }}
    
    # === SECURITY HEADERS ===
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # === PROXY TO ORIGIN ===
    location / {{
        proxy_pass {self.origin_proto}://origin_backend;
        proxy_http_version 1.1;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # SSL
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
    }}
    
    # === STATIC CACHING ===
    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {{
        proxy_pass {self.origin_proto}://origin_backend;
        proxy_cache_valid 200 30d;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }}
    
    # === HEALTH CHECK ===
    location /cdn-health {{
        access_log off;
        return 200 "OK - Mode: {mode}\\n";
        add_header Content-Type text/plain;
    }}
    
    # Блокируем .git, .env и т.д.
    location ~ /\\. {{
        deny all;
        access_log off;
        log_not_found off;
    }}
}}
"""
        
        os.makedirs("/etc/nginx/sites-available", exist_ok=True)
        os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)
        
        with open(self.nginx_site_config, "w") as f:
            f.write(site_conf)
        self.created_files.append(self.nginx_site_config)
        
        # Symlink
        if os.path.exists(self.nginx_site_enabled):
            os.remove(self.nginx_site_enabled)
        os.symlink(self.nginx_site_config, self.nginx_site_enabled)
        self.created_symlinks.append(self.nginx_site_enabled)
        
        # Удаляем default
        default_site = "/etc/nginx/sites-enabled/default"
        if os.path.exists(default_site):
            os.remove(default_site)
        
        print(f"{Colors.GREEN}✓ Nginx сконфигурирован (режим: {mode}){Colors.NC}")
    
    def start_nginx(self):
        """Запуск Nginx"""
        self._print_step("Запуск Nginx...")
        
        # Тест конфига
        result = self._run_command("nginx -t", check=False)
        if result.returncode != 0:
            print(f"{Colors.RED}✗ Ошибка конфигурации:{Colors.NC}")
            print(result.stderr)
            raise RuntimeError("Nginx config test failed")
        
        print(f"{Colors.GREEN}  ✓ Конфигурация валидна{Colors.NC}")
        
        # Запуск
        self._run_command("systemctl unmask nginx > /dev/null 2>&1", check=False)
        self._run_command("systemctl enable nginx > /dev/null 2>&1")
        self._run_command("systemctl restart nginx")
        
        time.sleep(1)
        result = self._run_command("systemctl is-active nginx", check=False)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓ Nginx запущен{Colors.NC}")
        else:
            raise RuntimeError("Nginx не запустился")
    
    def reload_nginx(self):
        """Перезагрузка конфига без остановки"""
        result = self._run_command("nginx -t", check=False)
        if result.returncode == 0:
            self._run_command("systemctl reload nginx", check=False)
    
    def switch_protection_mode(self, new_mode: str):
        """Переключение режима защиты"""
        if new_mode == self.current_mode:
            return
        
        print(f"\n{Colors.MAGENTA}╔{'═'*60}╗{Colors.NC}")
        print(f"{Colors.MAGENTA}║ ПЕРЕКЛЮЧЕНИЕ РЕЖИМА: {self.current_mode} → {new_mode}{Colors.NC}")
        print(f"{Colors.MAGENTA}╚{'═'*60}╝{Colors.NC}")
        
        # Обновляем конфиги
        self.configure_nginx(new_mode)
        self.update_iptables_limits(new_mode)
        self.reload_nginx()
        
        self.current_mode = new_mode
        
        print(f"{Colors.GREEN}✓ Режим изменен на {new_mode}{Colors.NC}\n")
    
    def get_nginx_rps(self) -> float:
        """Получение текущего RPS из логов Nginx"""
        try:
            # Берем последние 10 секунд логов
            result = self._run_command(
                "tail -n 1000 /var/log/nginx/access.log | "
                "awk '{print $4}' | "
                "cut -d: -f1-3 | "
                "uniq -c | "
                "tail -1 | "
                "awk '{print $1}'",
                check=False
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return float(result.stdout.strip()) / 10
            return 0.0
        except:
            return 0.0
    
    def attack_monitor(self):
        """Мониторинг атак и автоматическое переключение режимов"""
        print(f"\n{Colors.CYAN}▶ Запуск системы мониторинга атак...{Colors.NC}")
        
        while self.monitoring:
            time.sleep(5)
            
            rps = self.get_nginx_rps()
            
            # Логика переключения режимов
            if rps > WAR_MODE_THRESHOLD and self.current_mode != 'WAR':
                self.switch_protection_mode('WAR')
            elif rps > ATTACK_DETECTION_THRESHOLD and self.current_mode == 'NORMAL':
                self.switch_protection_mode('ALERT')
            elif rps < ATTACK_DETECTION_THRESHOLD / 2 and self.current_mode != 'NORMAL':
                # Возврат в нормальный режим
                self.switch_protection_mode('NORMAL')
            
            # Статус в консоль
            if rps > 0:
                mode_color = Colors.GREEN if self.current_mode == 'NORMAL' else (
                    Colors.YELLOW if self.current_mode == 'ALERT' else Colors.RED
                )
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] RPS: {rps:>6.1f} | Режим: {mode_color}{self.current_mode}{Colors.NC}")
    
    def cleanup(self):
        """Полная очистка"""
        print(f"\n{Colors.MAGENTA}>>> CLEANUP <<<{Colors.NC}")
        
        self.monitoring = False
        
        # Stop Nginx
        self._run_command("systemctl stop nginx", check=False)
        print("• Nginx остановлен")
        
        # Очистка файлов
        for symlink in self.created_symlinks:
            if os.path.islink(symlink):
                os.remove(symlink)
        
        for filepath in self.created_files:
            if os.path.exists(filepath):
                os.remove(filepath)
        print("• Файлы удалены")
        
        # Restore nginx.conf
        if os.path.exists(self.nginx_main_backup):
            shutil.copy(self.nginx_main_backup, "/etc/nginx/nginx.conf")
            os.remove(self.nginx_main_backup)
        
        # Очистка iptables
        if self.iptables_initialized:
            self._run_command("iptables -F", check=False)
            self._run_command("iptables -X", check=False)
            self._run_command("iptables -t mangle -F", check=False)
            self._run_command("iptables -t mangle -X", check=False)
            self._run_command("iptables -t raw -F", check=False)
            self._run_command("iptables -P INPUT ACCEPT", check=False)
            self._run_command("iptables -P FORWARD ACCEPT", check=False)
            print("• Iptables очищен")
        
        # Rollback sysctl
        self._run_command("sysctl --system > /dev/null 2>&1", check=False)
        
        print(f"{Colors.GREEN}✓ Система очищена{Colors.NC}")
    
    def run(self):
        """Главная функция запуска"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}Запускай от root!{Colors.NC}")
            sys.exit(1)
        
        print(f"{Colors.CYAN}{'='*70}{Colors.NC}")
        print(f"{Colors.CYAN}CDN DDoS PROTECTION v2 - MAXIMUM SECURITY{Colors.NC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.NC}")
        print(f"Target: {self.domain} -> {self.origin_ip}:{self.origin_port}")
        
        # Установка
        self.install_dependencies()
        self.configure_kernel_hardening()
        self.setup_iptables_ddos_protection()
        self.generate_ssl_cert()
        self.configure_nginx('NORMAL')
        self.start_nginx()
        
        # Запуск мониторинга в отдельном потоке
        self.monitor_thread = threading.Thread(target=self.attack_monitor, daemon=True)
        self.monitor_thread.start()
        
        # Статус
        print(f"\n{Colors.GREEN}╔{'═'*68}╗{Colors.NC}")
        print(f"{Colors.GREEN}║ {'ЗАЩИТА АКТИВНА':^68} ║{Colors.NC}")
        print(f"{Colors.GREEN}╚{'═'*68}╝{Colors.NC}")
        
        print(f"\n{Colors.CYAN}Многоуровневая защита:{Colors.NC}")
        print(f"  ✓ Kernel hardening (sysctl)")
        print(f"  ✓ Iptables DDoS фильтры")
        print(f"  ✓ Nginx adaptive rate limiting")
        print(f"  ✓ Auto attack detection")
        
        print(f"\n{Colors.CYAN}Режимы защиты:{Colors.NC}")
        print(f"  • NORMAL: {MODES['NORMAL'].req_rate}, burst {MODES['NORMAL'].req_burst}, conn {MODES['NORMAL'].conn_limit}")
        print(f"  • ALERT:  {MODES['ALERT'].req_rate}, burst {MODES['ALERT'].req_burst}, conn {MODES['ALERT'].conn_limit}")
        print(f"  • WAR:    {MODES['WAR'].req_rate}, burst {MODES['WAR'].req_burst}, conn {MODES['WAR'].conn_limit}")
        
        print(f"\n{Colors.CYAN}Адрес:{Colors.NC} https://{self.domain}")
        print(f"{Colors.CYAN}Health:{Colors.NC} https://{self.domain}/cdn-health")
        
        print(f"\n{Colors.YELLOW}Нажми Ctrl+C для остановки{Colors.NC}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    protection = CDNDDoSProtection(TARGET_DOMAIN, ORIGIN_IP, ORIGIN_PORT)
    protection.run()
