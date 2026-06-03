import re
from collections import Counter
from urllib.parse import unquote

def parse_log(lines):
    ips = []
    suspicious = []
    status_codes = Counter()
    hourly = Counter()
    
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(.*?)\].*?"([A-Z]+) ([^"]*) HTTP/[\d.]+"\s+(\d{3})')
    
    suspicious_patterns = ['/wp-login.php', '/wp-admin', '/.env', '../', 'eval(', 'union select', '<script>', '/etc/passwd', 'phpinfo', '/config.php']

    for line in lines:
        match = log_pattern.search(line)
        if match:
            ip = match.group(1)
            date_str = match.group(2)
            method = match.group(3)
            path = unquote(match.group(4))
            status = match.group(5)

            ips.append(ip)
            status_codes[status] += 1
            
            try:
                hour = int(date_str.split(':')[1])
                hourly[hour] += 1
            except:
                pass

            path_lower = path.lower()
            if any(p in path_lower for p in suspicious_patterns):
                suspicious.append({
                    'ip': ip,
                    'method': method,
                    'path': path,
                    'status': status,
                    'time': date_str
                })

    top_ips = Counter(ips).most_common(10)
    hourly_data = [hourly.get(h, 0) for h in range(24)]
    
    return {
        'top_ips': top_ips,
        'suspicious': suspicious[:50],
        'status_codes': status_codes.most_common(),
        'unique_ips': len(set(ips)),
        'hourly_data': hourly_data,
        'suspicious_ips': ','.join(set([s['ip'] for s in suspicious]))
    }