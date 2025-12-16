#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple CDN - Basic Reverse Proxy
=================================
Простой CDN без DDoS защиты - только проксирование
"""

import os
import sys
import signal
import subprocess
import shutil
import time
from pathlib import Path
from typing import List
import atexit

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

TARGET_DOMAIN = "daytepizdipz.hiend.shop"
ORIGIN_IP     = "94.159.100.238"
ORIGIN_PORT   = 443

# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

class SimpleCDN:
    def __init__(self, domain: str, origin_ip: str, origin_port: int = 443):
        self.domain = domain
        self.origin_ip = origin_ip
        self.origin_port = origin_port
        self.origin_proto = "https" if origin_port == 443 else "http"
        
        # Пути
        self.nginx_site_config = f"/etc/nginx/sites-available/{domain}"
        self.nginx_site_enabled = f"/etc/nginx/sites-enabled/{domain}"
        self.ssl_cert = "/etc/ssl/certs/nginx-selfsigned.crt"
        self.ssl_key = "/etc/ssl/private/nginx-selfsigned.key"
        
        # Состояние
        self.created_files: List[str] = []
        self.created_symlinks: List[str] = []
        self.nginx_was_installed = self._check_nginx_installed()
        
        # Хуки для очистки
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        atexit.register(self.cleanup)
        
    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Завершение...{Colors.NC}")
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
    
    def install_nginx(self):
        """Установка Nginx"""
        if self.nginx_was_installed:
            print(f"{Colors.YELLOW}  Nginx уже установлен{Colors.NC}")
            return
        
        self._print_step("Установка Nginx...")
        
        if Path("/etc/debian_version").exists():
            self._run_command("apt-get update -qq", check=False)
            self._run_command("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl > /dev/null 2>&1")
        elif Path("/etc/redhat-release").exists():
            self._run_command("yum install -y nginx openssl > /dev/null 2>&1")
        
        print(f"{Colors.GREEN}✓ Nginx установлен{Colors.NC}")
    
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
    
    def configure_nginx(self):
        """Простая конфигурация Nginx - только проксирование"""
        self._print_step("Конфигурация Nginx...")
        
        # Простой nginx.conf
        nginx_main_conf = """user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 2048;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""
        
        with open("/etc/nginx/nginx.conf", "w") as f:
            f.write(nginx_main_conf)
        
        # Простой конфиг сайта - только reverse proxy
        site_conf = f"""# Upstream
upstream origin_backend {{
    server {self.origin_ip}:{self.origin_port};
    keepalive 32;
}}

# HTTP -> HTTPS редирект
server {{
    listen 80;
    server_name {self.domain};
    
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# HTTPS сервер
server {{
    listen 443 ssl http2;
    server_name {self.domain};
    
    # SSL
    ssl_certificate {self.ssl_cert};
    ssl_certificate_key {self.ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Проксирование на origin
    location / {{
        proxy_pass {self.origin_proto}://origin_backend;
        proxy_http_version 1.1;
        
        # Базовые headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # SSL
        proxy_ssl_verify off;
    }}
    
    # Кеширование статики
    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {{
        proxy_pass {self.origin_proto}://origin_backend;
        expires 7d;
        add_header Cache-Control "public";
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
        
        print(f"{Colors.GREEN}✓ Nginx сконфигурирован (простой reverse proxy){Colors.NC}")
    
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
        self._run_command("systemctl enable nginx > /dev/null 2>&1", check=False)
        self._run_command("systemctl restart nginx")
        
        time.sleep(1)
        result = self._run_command("systemctl is-active nginx", check=False)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓ Nginx запущен{Colors.NC}")
        else:
            raise RuntimeError("Nginx не запустился")
    
    def cleanup(self):
        """Очистка"""
        print(f"\n{Colors.CYAN}>>> CLEANUP <<<{Colors.NC}")
        
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
        
        print(f"{Colors.GREEN}✓ Очистка завершена{Colors.NC}")
    
    def run(self):
        """Главная функция запуска"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}Запускай от root!{Colors.NC}")
            sys.exit(1)
        
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
        print(f"{Colors.CYAN}SIMPLE CDN - Reverse Proxy Only{Colors.NC}")
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
        print(f"Target: {self.domain} -> {self.origin_ip}:{self.origin_port}")
        
        # Установка и настройка
        self.install_nginx()
        self.generate_ssl_cert()
        self.configure_nginx()
        self.start_nginx()
        
        # Статус
        print(f"\n{Colors.GREEN}╔{'═'*58}╗{Colors.NC}")
        print(f"{Colors.GREEN}║ {'CDN ЗАПУЩЕН':^58} ║{Colors.NC}")
        print(f"{Colors.GREEN}╚{'═'*58}╝{Colors.NC}")
        
        print(f"\n{Colors.CYAN}Функции:{Colors.NC}")
        print(f"  ✓ Простое проксирование на origin")
        print(f"  ✓ SSL/TLS")
        print(f"  ✓ Кеширование статики")
        print(f"  ✓ HTTP/2")
        
        print(f"\n{Colors.CYAN}Адрес:{Colors.NC} https://{self.domain}")
        print(f"\n{Colors.YELLOW}Нажми Ctrl+C для остановки{Colors.NC}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    cdn = SimpleCDN(TARGET_DOMAIN, ORIGIN_IP, ORIGIN_PORT)
    cdn.run()
