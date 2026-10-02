#!/usr/bin/env python3
import random
import datetime
import sys
import os

# Configuration
DEFAULT_LINES = 10000
OUTPUT_FILE = "server.log"

# Normal IPs (internal/private)
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.22", "192.168.1.30",
    "10.0.0.5", "10.0.0.12", "10.0.0.100", "172.16.0.8"
]

# Suspicious IPs (public, often used in attacks)
MALICIOUS_IPS = [
    "45.33.32.156", "185.220.101.1", "104.248.0.1", "198.51.100.23",
    "203.0.113.45", "91.219.236.2", "5.188.62.14", "185.130.5.253",
    "103.41.124.10", "196.52.43.55"
]

# Normal user agents
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

# Suspicious user agents
MALICIOUS_UAS = [
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Wget/1.21.3",
    "Go-http-client/1.1",
    "zgrab/0.x",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"  # fake bot
]

# Normal paths
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/product/123",
    "/images/logo.png", "/css/style.css", "/js/app.js", "/api/v1/users",
    "/api/v1/orders", "/login", "/logout", "/dashboard", "/favicon.ico"
]

# Suspicious paths (SQLi, XSS, traversal, command injection, scanning)
SUSPICIOUS_PATHS = [
    # SQL Injection
    "/search?q=1' OR '1'='1",
    "/product?id=1 UNION SELECT username, password FROM users--",
    "/login?username=admin'--&password=anything",
    "/api/v1/users?id=1; DROP TABLE users--",
    "/search?q=1' AND 1=1--",
    # XSS
    "/comment?text=<script>alert('XSS')</script>",
    "/profile?name=<img src=x onerror=alert(1)>",
    "/search?q=<svg/onload=alert(1)>",
    # Path Traversal
    "/../../etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "/download?file=../../../../etc/shadow",
    "/static/..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    # Command Injection
    "/ping?ip=127.0.0.1;cat /etc/passwd",
    "/exec?cmd=whoami",
    "/system?command=ls -la",
    # Scanning / Admin probing
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php",
    "/backup.zip", "/db.sql", "/.git/config", "/server-status",
    "/actuator/health", "/console", "/manager/html"
]

# HTTP methods
METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

# Status codes with weights
STATUS_CODES = [200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 404, 500, 502, 503]

def random_timestamp(start_time, increment_seconds):
    """Generate a timestamp string in common log format."""
    dt = start_time + datetime.timedelta(seconds=increment_seconds)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def generate_log_line(timestamp, ip, method, path, status, size, referer, user_agent):
    """Format a single log line in Combined Log Format."""
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'

def main():
    lines_count = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LINES
    output_file = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_FILE

    # Start time: 30 days ago
    start_time = datetime.datetime.now() - datetime.timedelta(days=30)
    current_time = start_time

    # For brute force burst: pick a malicious IP and generate many login attempts
    brute_force_ip = random.choice(MALICIOUS_IPS)
    brute_force_start = random.randint(1000, lines_count - 500)
    brute_force_length = random.randint(50, 200)

    with open(output_file, "w") as f:
        for i in range(lines_count):
            # Advance time by 1-30 seconds randomly
            current_time += datetime.timedelta(seconds=random.randint(1, 30))
            timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")

            # Decide if this is a suspicious request (30% chance) or normal
            is_suspicious = random.random() < 0.30

            # Special brute force burst
            if brute_force_start <= i < brute_force_start + brute_force_length:
                ip = brute_force_ip
                method = "POST"
                path = "/login"
                status = random.choice([200, 401, 401, 401, 403])
                size = random.randint(200, 1000)
                referer = "-"
                user_agent = random.choice(MALICIOUS_UAS)
            else:
                if is_suspicious:
                    ip = random.choice(MALICIOUS_IPS)
                    method = random.choice(["GET", "POST", "HEAD", "OPTIONS"])
                    path = random.choice(SUSPICIOUS_PATHS)
                    status = random.choice([200, 403, 404, 500, 400, 401])
                    size = random.randint(0, 5000)
                    referer = random.choice(["-", "http://evil.com/", "http://localhost/"])
                    user_agent = random.choice(MALICIOUS_UAS)
                else:
                    ip = random.choice(NORMAL_IPS)
                    method = random.choice(METHODS)
                    path = random.choice(NORMAL_PATHS)
                    status = random.choice(STATUS_CODES)
                    size = random.randint(100, 20000)
                    referer = random.choice(["-", "http://localhost/", "https://example.com/"])
                    user_agent = random.choice(NORMAL_UAS)

            line = generate_log_line(timestamp, ip, method, path, status, size, referer, user_agent)
            f.write(line + "\n")

    print(f"Generated {lines_count} lines in {output_file}")

if __name__ == "__main__":
    main()