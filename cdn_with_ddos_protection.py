#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker CDN with DDoS Protection
================================
Reverse Proxy в Docker контейнере с продвинутой защитой от DDoS атак
"""

import os
import sys
import signal
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Optional
import atexit

# Импорт модуля DDoS защиты
try:
    from ddos_protection import (
        DDoSProtectionConfig,
        NginxDDoSProtection,
        ProtectionProfiles
    )
except ImportError:
    print("❌ Ошибка: не найден модуль ddos_protection.py")
    print("   Убедись что ddos_protection.py находится в той же директории")
    sys.exit(1)

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

TARGET_DOMAIN = "daytepizdipz.hiend.shop"
ORIGIN_IP = "94.159.100.238"
ORIGIN_PORT = 443

# Пути для Docker
DOCKER_DIR = "/opt/cdn-docker"
NGINX_CONFIG_DIR = f"{DOCKER_DIR}/nginx"
SSL_DIR = f"{DOCKER_DIR}/ssl"

# Профиль DDoS защиты: 'basic', 'strict', 'performance', 'paranoid'
DDOS_PROFILE = 'strict'  # Измени на нужный профиль

# ============================================================================

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'


class DockerCDNWithDDoSProtection:
    """CDN с интегрированной DDoS защитой"""

    def __init__(
        self,
        domain: str,
        origin_ip: str,
        origin_port: int = 443,
        ddos_profile: str = 'basic'
    ):
        self.domain = domain
        self.origin_ip = origin_ip
        self.origin_port = origin_port
        self.origin_proto = "https" if origin_port == 443 else "http"

        # Пути
        self.docker_dir = DOCKER_DIR
        self.nginx_config_dir = NGINX_CONFIG_DIR
        self.ssl_dir = SSL_DIR
        self.compose_file = f"{DOCKER_DIR}/docker-compose.yml"
        self.nginx_conf = f"{NGINX_CONFIG_DIR}/nginx.conf"
        self.ssl_cert = f"{SSL_DIR}/nginx.crt"
        self.ssl_key = f"{SSL_DIR}/nginx.key"

        # Состояние
        self.created_dirs: List[str] = []
        self.docker_installed = False
        self.container_name = "cdn-nginx-protected"

        # DDoS Protection
        self.ddos_profile = ddos_profile
        self.ddos_config = self._get_ddos_config(ddos_profile)
        self.ddos_protection = NginxDDoSProtection(self.ddos_config)

        # Хуки
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        atexit.register(self.cleanup)

    def _get_ddos_config(self, profile: str) -> DDoSProtectionConfig:
        """Получение конфигурации DDoS защиты по профилю"""
        profiles = {
            'basic': ProtectionProfiles.basic,
            'strict': ProtectionProfiles.strict,
            'performance': ProtectionProfiles.performance,
            'paranoid': ProtectionProfiles.paranoid,
        }

        if profile not in profiles:
            print(f"{Colors.YELLOW}⚠ Неизвестный профиль '{profile}', использую 'basic'{Colors.NC}")
            profile = 'basic'

        return profiles[profile]()

    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Завершение...{Colors.NC}")
        sys.exit(0)

    def _run_command(
        self,
        cmd: str,
        shell: bool = True,
        check: bool = True
    ) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd,
                shell=shell,
                check=check,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            if check:
                print(f"{Colors.RED}✗ Ошибка: {cmd}{Colors.NC}")
                if e.stderr:
                    print(f"{Colors.RED}  {e.stderr[:300]}{Colors.NC}")
            raise

    def _print_step(self, message: str):
        print(f"\n{Colors.CYAN}▶ {message}{Colors.NC}")

    def check_docker_installed(self) -> bool:
        """Проверка установлен ли Docker"""
        return shutil.which('docker') is not None

    def install_docker(self):
        """Автоматическая установка Docker"""
        if self.check_docker_installed():
            print(f"{Colors.YELLOW}  Docker уже установлен{Colors.NC}")
            self.docker_installed = True
            return

        self._print_step("Установка Docker...")

        try:
            print(f"{Colors.CYAN}  Скачивание официального установщика...{Colors.NC}")
            self._run_command("curl -fsSL https://get.docker.com -o /tmp/get-docker.sh")

            print(f"{Colors.CYAN}  Установка Docker Engine...{Colors.NC}")
            self._run_command("sh /tmp/get-docker.sh")

            # Запуск Docker
            self._run_command("systemctl start docker")
            self._run_command("systemctl enable docker")

            # Проверка
            result = self._run_command("docker --version", check=False)
            if result.returncode == 0:
                print(f"{Colors.GREEN}✓ Docker установлен: {result.stdout.strip()}{Colors.NC}")
                self.docker_installed = True
            else:
                raise RuntimeError("Docker не установился корректно")

        except Exception as e:
            print(f"{Colors.RED}✗ Ошибка установки Docker: {e}{Colors.NC}")
            print(f"{Colors.YELLOW}Попробуйте установить вручную: curl -fsSL https://get.docker.com | sh{Colors.NC}")
            sys.exit(1)

    def create_directories(self):
        """Создание рабочих директорий"""
        self._print_step("Создание директорий...")

        dirs = [self.docker_dir, self.nginx_config_dir, self.ssl_dir]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
            self.created_dirs.append(d)

        print(f"{Colors.GREEN}✓ Директории созданы в {self.docker_dir}{Colors.NC}")

    def generate_ssl_cert(self):
        """Генерация SSL сертификата"""
        self._print_step("Генерация SSL сертификата...")

        if os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
            print(f"{Colors.YELLOW}  Сертификат уже существует{Colors.NC}")
            return

        cmd = (
            f'openssl req -x509 -nodes -days 365 -newkey rsa:2048 '
            f'-keyout {self.ssl_key} '
            f'-out {self.ssl_cert} '
            f'-subj "/C=RU/ST=Moscow/L=Moscow/O=CDN/CN={self.domain}"'
        )

        self._run_command(cmd)
        print(f"{Colors.GREEN}✓ SSL сертификат создан{Colors.NC}")

    def create_nginx_config(self):
        """Создание конфигурации Nginx с DDoS защитой"""
        self._print_step("Создание конфигурации Nginx с DDoS защитой...")

        # Генерация правил DDoS защиты
        http_ddos_config = self.ddos_protection.generate_http_section()
        location_ddos_rules = self.ddos_protection.generate_server_location_rules()

        nginx_conf = f"""user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {{
    worker_connections 2048;
    use epoll;
    multi_accept on;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    log_format security '$remote_addr - [$time_local] "$request" '
                        '$status "$http_user_agent" - Blocked';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    server_tokens off;

    # ========================================================================
    # DDOS PROTECTION - Автоматически сгенерировано модулем ddos_protection
    # ========================================================================
{http_ddos_config}
    # ========================================================================

    # Upstream к origin серверу
    upstream origin_backend {{
        server {self.origin_ip}:{self.origin_port};
        keepalive 32;
        keepalive_requests 100;
        keepalive_timeout 60s;
    }}

    # HTTP -> HTTPS редирект
    server {{
        listen 80;
        server_name {self.domain};

        location / {{
            return 301 https://$host$request_uri;
        }}
    }}

    # HTTPS сервер с DDoS защитой
    server {{
        listen 443 ssl http2;
        server_name {self.domain};

        # SSL конфигурация
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Основной location с DDoS защитой
        location / {{
{location_ddos_rules}
            # Reverse proxy к origin
            proxy_pass {self.origin_proto}://origin_backend;
            proxy_http_version 1.1;

            # Headers
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;

            # Buffering
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 8 4k;

            # SSL для upstream
            proxy_ssl_verify off;
            proxy_ssl_server_name on;
        }}

        # Кеширование статики
        location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {{
            proxy_pass {self.origin_proto}://origin_backend;
            proxy_set_header Host $host;
            expires 7d;
            add_header Cache-Control "public";
        }}

        # Health check
        location /cdn-health {{
            access_log off;
            return 200 "CDN with DDoS Protection OK\\n";
            add_header Content-Type text/plain;
        }}

        # DDoS Protection Status
        location /ddos-status {{
            access_log off;
            return 200 "DDoS Protection: {self.ddos_profile.upper()} profile active\\n";
            add_header Content-Type text/plain;
        }}
    }}
}}
"""

        with open(self.nginx_conf, "w") as f:
            f.write(nginx_conf)

        print(f"{Colors.GREEN}✓ Nginx конфиг с DDoS защитой создан: {self.nginx_conf}{Colors.NC}")

    def create_docker_compose(self):
        """Создание docker-compose.yml"""
        self._print_step("Создание docker-compose.yml...")

        compose_content = f"""services:
  nginx:
    image: nginx:alpine
    container_name: {self.container_name}
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - {self.nginx_config_dir}/nginx.conf:/etc/nginx/nginx.conf:ro
      - {self.ssl_dir}:/etc/nginx/ssl:ro
    networks:
      - cdn-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  cdn-network:
    driver: bridge
"""

        with open(self.compose_file, "w") as f:
            f.write(compose_content)

        print(f"{Colors.GREEN}✓ docker-compose.yml создан{Colors.NC}")

    def start_docker_compose(self):
        """Запуск Docker Compose"""
        self._print_step("Запуск Docker контейнера с DDoS защитой...")

        # Остановка старых контейнеров
        self._run_command(f"cd {self.docker_dir} && docker compose down", check=False)

        # Запуск
        result = self._run_command(f"cd {self.docker_dir} && docker compose up -d")

        if result.returncode == 0:
            time.sleep(2)

            # Проверка статуса
            status = self._run_command(
                f"docker ps --filter name={self.container_name} --format '{{{{.Status}}}}'",
                check=False
            )

            if "Up" in status.stdout:
                print(f"{Colors.GREEN}✓ Контейнер {self.container_name} запущен{Colors.NC}")
                return True
            else:
                print(f"{Colors.RED}✗ Контейнер не запустился{Colors.NC}")
                logs = self._run_command(f"docker logs {self.container_name}", check=False)
                print(logs.stdout)
                return False
        else:
            print(f"{Colors.RED}✗ Ошибка запуска docker compose{Colors.NC}")
            return False

    def show_ddos_protection_info(self):
        """Показать информацию о DDoS защите"""
        print(f"\n{Colors.BLUE}╔{'═'*68}╗{Colors.NC}")
        print(f"{Colors.BLUE}║ {'🛡️  DDOS PROTECTION STATUS':^68} ║{Colors.NC}")
        print(f"{Colors.BLUE}╚{'═'*68}╝{Colors.NC}")

        print(f"\n{Colors.CYAN}Активный профиль: {Colors.GREEN}{self.ddos_profile.upper()}{Colors.NC}")
        print(f"\n{Colors.CYAN}Активные правила защиты:{Colors.NC}")

        summary = self.ddos_protection.get_protection_summary()
        for key, value in summary.items():
            status_color = Colors.GREEN if value != "Disabled" else Colors.YELLOW
            print(f"  • {key:.<30} {status_color}{value}{Colors.NC}")

    def show_status(self):
        """Показ статуса контейнера"""
        print(f"\n{Colors.CYAN}▶ Статус контейнера:{Colors.NC}")
        self._run_command(f"docker ps --filter name={self.container_name}", check=False)

        print(f"\n{Colors.CYAN}▶ Логи (последние 15 строк):{Colors.NC}")
        self._run_command(f"docker logs --tail 15 {self.container_name}", check=False)

    def cleanup(self):
        """Остановка и очистка"""
        print(f"\n{Colors.MAGENTA}>>> CLEANUP <<<{Colors.NC}")

        # Остановка контейнера
        print(f"{Colors.CYAN}  Остановка контейнера...{Colors.NC}")
        self._run_command(f"cd {self.docker_dir} && docker compose down", check=False)

        print(f"{Colors.GREEN}✓ Контейнер остановлен{Colors.NC}")
        print(f"{Colors.YELLOW}  Файлы сохранены в {self.docker_dir}{Colors.NC}")

    def run(self):
        """Главная функция запуска"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}❌ Запускай от root!{Colors.NC}")
            sys.exit(1)

        print(f"{Colors.CYAN}{'='*70}{Colors.NC}")
        print(f"{Colors.CYAN}🛡️  DOCKER CDN WITH DDOS PROTECTION{Colors.NC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.NC}")
        print(f"Target: {self.domain} -> {self.origin_ip}:{self.origin_port}")
        print(f"DDoS Profile: {Colors.GREEN}{self.ddos_profile.upper()}{Colors.NC}")

        # Установка и настройка
        self.install_docker()
        self.create_directories()
        self.generate_ssl_cert()
        self.create_nginx_config()
        self.create_docker_compose()

        # Запуск
        if self.start_docker_compose():
            # Успешный запуск
            print(f"\n{Colors.GREEN}╔{'═'*68}╗{Colors.NC}")
            print(f"{Colors.GREEN}║ {'✅ CDN С DDOS ЗАЩИТОЙ ЗАПУЩЕН':^68} ║{Colors.NC}")
            print(f"{Colors.GREEN}╚{'═'*68}╝{Colors.NC}")

            print(f"\n{Colors.CYAN}Конфигурация:{Colors.NC}")
            print(f"  📁 Директория: {self.docker_dir}")
            print(f"  🐳 Контейнер: {self.container_name}")
            print(f"  📝 Nginx config: {self.nginx_conf}")
            print(f"  🔒 SSL: {self.ssl_dir}")

            print(f"\n{Colors.CYAN}Функции:{Colors.NC}")
            print(f"  ✓ Изолированный Docker контейнер")
            print(f"  ✓ Nginx Alpine (минимальный образ)")
            print(f"  ✓ Reverse proxy на origin")
            print(f"  ✓ SSL/TLS")
            print(f"  ✓ Кеширование статики")
            print(f"  ✓ Auto-restart при падении")
            print(f"  ✓ {Colors.GREEN}DDoS Protection ({self.ddos_profile}){Colors.NC}")

            # Показать статус DDoS защиты
            self.show_ddos_protection_info()

            print(f"\n{Colors.CYAN}Доступ:{Colors.NC}")
            print(f"  🌐 https://{self.domain}")
            print(f"  ❤️  https://{self.domain}/cdn-health")
            print(f"  🛡️  https://{self.domain}/ddos-status")

            print(f"\n{Colors.CYAN}Управление:{Colors.NC}")
            print(f"  • Логи: docker logs -f {self.container_name}")
            print(f"  • Рестарт: cd {self.docker_dir} && docker compose restart")
            print(f"  • Стоп: cd {self.docker_dir} && docker compose down")
            print(f"  • Старт: cd {self.docker_dir} && docker compose up -d")

            print(f"\n{Colors.MAGENTA}💡 Настройка DDoS защиты:{Colors.NC}")
            print(f"  • Профили: basic, strict, performance, paranoid")
            print(f"  • Измени DDOS_PROFILE в начале скрипта")
            print(f"  • Или редактируй ddos_protection.py для кастомных правил")

            self.show_status()

            print(f"\n{Colors.YELLOW}Нажми Ctrl+C для остановки{Colors.NC}\n")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            print(f"\n{Colors.RED}❌ Не удалось запустить контейнер{Colors.NC}")
            sys.exit(1)


if __name__ == '__main__':
    cdn = DockerCDNWithDDoSProtection(
        TARGET_DOMAIN,
        ORIGIN_IP,
        ORIGIN_PORT,
        ddos_profile=DDOS_PROFILE
    )
    cdn.run()
