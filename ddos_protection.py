#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Protection Module
======================
Модуль для генерации правил защиты от DDoS атак для Nginx

Основные механизмы защиты:
1. Rate Limiting - ограничение частоты запросов
2. Connection Limiting - ограничение количества соединений
3. Request Size Limiting - ограничение размера запросов
4. Request Validation - валидация HTTP запросов
5. IP Blacklisting - блокировка подозрительных IP
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class DDoSProtectionConfig:
    """Конфигурация DDoS защиты"""

    # Rate Limiting (запросы в секунду на IP)
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 10  # запросов в секунду
    rate_limit_burst: int = 20  # буфер для всплесков

    # Connection Limiting (соединения на IP)
    conn_limit_enabled: bool = True
    conn_limit_connections: int = 10  # одновременных соединений

    # Request Size Limiting
    request_size_limit_enabled: bool = True
    client_body_size: str = "10m"  # максимальный размер тела запроса
    client_header_buffer_size: str = "1k"
    large_client_header_buffers: str = "4 8k"

    # Timeouts (защита от slowloris)
    timeout_protection_enabled: bool = True
    client_body_timeout: int = 10  # секунд
    client_header_timeout: int = 10  # секунд
    send_timeout: int = 10  # секунд
    keepalive_timeout: int = 15  # секунд
    keepalive_requests: int = 100

    # Request Validation
    request_validation_enabled: bool = True
    block_suspicious_user_agents: bool = True
    block_suspicious_requests: bool = True

    # IP Blacklist
    ip_blacklist_enabled: bool = True
    blacklisted_ips: List[str] = field(default_factory=list)

    # IP Whitelist (доверенные IP, не ограничиваются)
    ip_whitelist_enabled: bool = False
    whitelisted_ips: List[str] = field(default_factory=list)

    # Geo-blocking (страны для блокировки, требует GeoIP модуль)
    geo_blocking_enabled: bool = False
    blocked_countries: List[str] = field(default_factory=list)

    # Дополнительная защита
    fail2ban_integration: bool = True
    log_suspicious_activity: bool = True


class NginxDDoSProtection:
    """Генератор конфигурации Nginx с DDoS защитой"""

    def __init__(self, config: Optional[DDoSProtectionConfig] = None):
        self.config = config or DDoSProtectionConfig()

    def generate_rate_limit_zone(self) -> str:
        """Генерация зоны для rate limiting"""
        if not self.config.rate_limit_enabled:
            return ""

        return f"""
    # Rate Limiting Zone - защита от flood атак
    limit_req_zone $binary_remote_addr zone=ddos_rate_limit:10m rate={self.config.rate_limit_requests}r/s;
    limit_req_status 429;  # Too Many Requests
"""

    def generate_conn_limit_zone(self) -> str:
        """Генерация зоны для connection limiting"""
        if not self.config.conn_limit_enabled:
            return ""

        return f"""
    # Connection Limiting Zone - защита от множественных соединений
    limit_conn_zone $binary_remote_addr zone=ddos_conn_limit:10m;
    limit_conn_status 429;
"""

    def generate_request_validation_map(self) -> str:
        """Генерация карты для валидации запросов"""
        if not self.config.request_validation_enabled:
            return ""

        validation = """
    # Блокировка подозрительных User-Agent
    map $http_user_agent $bad_bot {
        default 0;
        ~*(?i)(bot|crawler|spider|scraper) 0;  # разрешённые боты
        ~*(?i)(nikto|sqlmap|nmap|masscan|metasploit) 1;  # сканеры
        ~*(?i)(curl|wget|python|perl|ruby) 1;  # CLI инструменты
        "" 1;  # пустой user-agent
    }

    # Блокировка подозрительных HTTP методов
    map $request_method $bad_method {
        default 0;
        GET 0;
        POST 0;
        HEAD 0;
        OPTIONS 0;
        ~*(TRACE|TRACK|DELETE|PUT|CONNECT) 1;
    }

    # Блокировка подозрительных URL паттернов
    map $request_uri $bad_uri {
        default 0;
        ~*(/\.env|/\.git|/\.svn|/\.hg) 1;  # скрытые файлы
        ~*(phpMyAdmin|phpmyadmin|pma|admin) 1;  # админ панели
        ~*(eval\\(|base64_decode|gzinflate) 1;  # PHP инъекции
        ~*(UNION.*SELECT|INSERT.*INTO|DROP.*TABLE) 1;  # SQL инъекции
        ~*(<script|javascript:|onerror=) 1;  # XSS
    }
"""
        return validation

    def generate_ip_blacklist_map(self) -> str:
        """Генерация карты для блокировки IP"""
        if not self.config.ip_blacklist_enabled or not self.config.blacklisted_ips:
            return ""

        blacklist = "\n    # IP Blacklist\n    map $remote_addr $blocked_ip {\n        default 0;\n"
        for ip in self.config.blacklisted_ips:
            blacklist += f"        {ip} 1;\n"
        blacklist += "    }\n"

        return blacklist

    def generate_ip_whitelist_map(self) -> str:
        """Генерация карты для whitelist IP"""
        if not self.config.ip_whitelist_enabled or not self.config.whitelisted_ips:
            return ""

        whitelist = "\n    # IP Whitelist (доверенные IP)\n    map $remote_addr $whitelisted_ip {\n        default 0;\n"
        for ip in self.config.whitelisted_ips:
            whitelist += f"        {ip} 1;\n"
        whitelist += "    }\n"

        return whitelist

    def generate_geo_blocking_map(self) -> str:
        """Генерация карты для geo-blocking (требует GeoIP)"""
        if not self.config.geo_blocking_enabled or not self.config.blocked_countries:
            return ""

        geo_block = "\n    # Geo-blocking (требует ngx_http_geoip_module)\n"
        geo_block += "    map $geoip_country_code $blocked_country {\n        default 0;\n"
        for country in self.config.blocked_countries:
            geo_block += f"        {country} 1;\n"
        geo_block += "    }\n"

        return geo_block

    def generate_http_section(self) -> str:
        """Генерация секции http с настройками защиты"""
        http_config = []

        # Rate limiting
        http_config.append(self.generate_rate_limit_zone())

        # Connection limiting
        http_config.append(self.generate_conn_limit_zone())

        # Request validation
        http_config.append(self.generate_request_validation_map())

        # IP whitelist
        http_config.append(self.generate_ip_whitelist_map())

        # IP blacklist
        http_config.append(self.generate_ip_blacklist_map())

        # Geo-blocking
        http_config.append(self.generate_geo_blocking_map())

        # Request size limits
        if self.config.request_size_limit_enabled:
            http_config.append(f"""
    # Ограничение размера запросов
    client_max_body_size {self.config.client_body_size};
    client_body_buffer_size 128k;
    client_header_buffer_size {self.config.client_header_buffer_size};
    large_client_header_buffers {self.config.large_client_header_buffers};
""")

        # Timeouts
        if self.config.timeout_protection_enabled:
            http_config.append(f"""
    # Защита от slowloris и slow POST атак
    client_body_timeout {self.config.client_body_timeout}s;
    client_header_timeout {self.config.client_header_timeout}s;
    send_timeout {self.config.send_timeout}s;
    keepalive_timeout {self.config.keepalive_timeout}s;
    keepalive_requests {self.config.keepalive_requests};
    reset_timedout_connection on;
""")

        return "".join(http_config)

    def generate_server_location_rules(self) -> str:
        """Генерация правил для location в server блоке"""
        rules = []

        # IP Whitelist (доверенные IP пропускаются без проверок)
        if self.config.ip_whitelist_enabled and self.config.whitelisted_ips:
            rules.append("""
            # IP Whitelist - доверенные IP пропускаются без ограничений
            if ($whitelisted_ip) {
                set $rate_limit_bypass 1;
            }
""")

        # Rate limiting (пропускаем для whitelist)
        if self.config.rate_limit_enabled:
            rules.append(f"""
            # Rate limiting
            limit_req zone=ddos_rate_limit burst={self.config.rate_limit_burst} nodelay;
""")

        # Connection limiting
        if self.config.conn_limit_enabled:
            rules.append(f"""
            # Connection limiting
            limit_conn ddos_conn_limit {self.config.conn_limit_connections};
""")

        # Request validation
        if self.config.request_validation_enabled:
            rules.append("""
            # Блокировка подозрительных запросов
            if ($bad_bot) {
                return 403 "Bot blocked";
            }
            if ($bad_method) {
                return 405 "Method not allowed";
            }
            if ($bad_uri) {
                return 403 "Suspicious request";
            }
""")

        # IP blacklist
        if self.config.ip_blacklist_enabled and self.config.blacklisted_ips:
            rules.append("""
            # IP blacklist
            if ($blocked_ip) {
                return 403 "IP blocked";
            }
""")

        # Geo-blocking
        if self.config.geo_blocking_enabled and self.config.blocked_countries:
            rules.append("""
            # Geo-blocking
            if ($blocked_country) {
                return 403 "Country blocked";
            }
""")

        return "".join(rules)

    def generate_fail2ban_config(self) -> str:
        """Генерация конфигурации для Fail2ban"""
        if not self.config.fail2ban_integration:
            return ""

        return """# Fail2ban filter для Nginx DDoS защиты
# Сохрани в /etc/fail2ban/filter.d/nginx-ddos.conf

[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*" (403|429|444)
ignoreregex =

# Jail конфигурация для /etc/fail2ban/jail.local:
# [nginx-ddos]
# enabled = true
# port = http,https
# logpath = /var/log/nginx/access.log
# maxretry = 10
# findtime = 60
# bantime = 3600
"""

    def get_protection_summary(self) -> Dict[str, str]:
        """Возвращает сводку активных правил защиты"""
        summary = {
            "Rate Limiting": f"{self.config.rate_limit_requests} req/s (burst: {self.config.rate_limit_burst})" if self.config.rate_limit_enabled else "Disabled",
            "Connection Limiting": f"{self.config.conn_limit_connections} connections" if self.config.conn_limit_enabled else "Disabled",
            "Request Size Limit": self.config.client_body_size if self.config.request_size_limit_enabled else "Disabled",
            "Timeout Protection": "Enabled" if self.config.timeout_protection_enabled else "Disabled",
            "Request Validation": "Enabled" if self.config.request_validation_enabled else "Disabled",
            "IP Whitelist": f"{len(self.config.whitelisted_ips)} trusted IPs" if self.config.ip_whitelist_enabled else "Disabled",
            "IP Blacklist": f"{len(self.config.blacklisted_ips)} IPs blocked" if self.config.ip_blacklist_enabled else "Disabled",
            "Geo-blocking": f"{len(self.config.blocked_countries)} countries blocked" if self.config.geo_blocking_enabled else "Disabled",
            "Fail2ban Integration": "Enabled" if self.config.fail2ban_integration else "Disabled",
        }
        return summary


# Предустановленные профили защиты
class ProtectionProfiles:
    """Предустановленные профили защиты"""

    @staticmethod
    def basic() -> DDoSProtectionConfig:
        """Базовая защита - подходит для большинства сайтов"""
        return DDoSProtectionConfig(
            rate_limit_requests=10,
            rate_limit_burst=20,
            conn_limit_connections=10,
        )

    @staticmethod
    def strict() -> DDoSProtectionConfig:
        """Строгая защита - безопасность без убийства сервера"""
        return DDoSProtectionConfig(
            rate_limit_requests=15,
            rate_limit_burst=30,
            conn_limit_connections=15,
            client_body_size="10m",
            client_body_timeout=15,
            client_header_timeout=15,
            send_timeout=15,
            keepalive_timeout=30,
        )

    @staticmethod
    def performance() -> DDoSProtectionConfig:
        """Оптимизированная для производительности"""
        return DDoSProtectionConfig(
            rate_limit_requests=50,
            rate_limit_burst=100,
            conn_limit_connections=50,
            client_body_size="20m",
        )

    @staticmethod
    def paranoid() -> DDoSProtectionConfig:
        """Параноидальная защита - блокирует почти всё"""
        return DDoSProtectionConfig(
            rate_limit_requests=2,
            rate_limit_burst=5,
            conn_limit_connections=3,
            client_body_size="1m",
            client_body_timeout=3,
            client_header_timeout=3,
            send_timeout=3,
            keepalive_timeout=5,
            block_suspicious_user_agents=True,
            block_suspicious_requests=True,
        )


if __name__ == '__main__':
    # Пример использования
    print("DDoS Protection Module - Примеры конфигураций\n")
    print("=" * 70)

    # Базовая защита
    basic_config = ProtectionProfiles.basic()
    protection = NginxDDoSProtection(basic_config)

    print("\n📊 БАЗОВАЯ ЗАЩИТА:")
    for key, value in protection.get_protection_summary().items():
        print(f"  • {key}: {value}")

    print("\n" + "=" * 70)
    print("Используй эти профили в своем коде:")
    print("  - ProtectionProfiles.basic()      # Базовая")
    print("  - ProtectionProfiles.strict()     # Строгая")
    print("  - ProtectionProfiles.performance() # Производительность")
    print("  - ProtectionProfiles.paranoid()   # Параноидальная")
