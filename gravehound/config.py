from dotenv import load_dotenv
load_dotenv()

APP_NAME = 'Gravehound'
APP_VERSION = '1.0.0'
APP_DESCRIPTION = 'Automated OSINT Recon Tool'
APP_URL = 'https://github.com/WIzbisy/gravehound'
DEFAULT_TIMEOUT = 10
DEFAULT_PORT_TIMEOUT = 1.5
DEFAULT_THREADS = 50
DEFAULT_DNS_TIMEOUT = 15
TOP_PORTS = [20, 21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 119, 135, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1433, 1434, 1521, 1720, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2096, 2222, 3000, 3306, 3389, 3690, 4000, 4443, 4444, 4567, 4848, 5000, 5432, 5555, 5672, 5900, 5901, 5984, 6379, 6667, 7001, 7002, 8000, 8008, 8080, 8081, 8443, 8880, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 25565, 27017, 27018, 28017, 32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 50000, 50070, 61616, 65535]
PORT_SERVICES = {20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 119: 'NNTP', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP (Submission)', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1434: 'MSSQL UDP', 1521: 'Oracle DB', 1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL', 2222: 'SSH Alt', 3000: 'Dev Server', 3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS Alt', 5000: 'Dev Server', 5432: 'PostgreSQL', 5672: 'RabbitMQ', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 6667: 'IRC', 7001: 'WebLogic', 8000: 'HTTP Alt', 8008: 'HTTP Alt', 8080: 'HTTP Proxy', 8081: 'HTTP Alt', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9000: 'PHP-FPM', 9090: 'Web Admin', 9200: 'Elasticsearch', 9418: 'Git', 10000: 'Webmin', 11211: 'Memcached', 25565: 'Minecraft', 27017: 'MongoDB', 50000: 'SAP', 61616: 'ActiveMQ'}
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
SECURITY_HEADERS = {'Strict-Transport-Security': {'description': 'HSTS: Forces HTTPS connections', 'severity': 'HIGH'}, 'Content-Security-Policy': {'description': 'CSP: Prevents XSS and injection attacks', 'severity': 'HIGH'}, 'X-Frame-Options': {'description': 'Prevents clickjacking attacks', 'severity': 'MEDIUM'}, 'X-Content-Type-Options': {'description': 'Prevents MIME-type sniffing', 'severity': 'MEDIUM'}, 'X-XSS-Protection': {'description': 'Legacy XSS filter (deprecated but still checked)', 'severity': 'LOW'}, 'Referrer-Policy': {'description': 'Controls referrer information leakage', 'severity': 'MEDIUM'}, 'Permissions-Policy': {'description': 'Controls browser feature access', 'severity': 'MEDIUM'}, 'X-Permitted-Cross-Domain-Policies': {'description': 'Controls Adobe Flash/PDF cross-domain access', 'severity': 'LOW'}}
BANNER = '\n   ██████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ \n  ██╔════╝ ██╔══██╗██╔══██╗██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗\n  ██║  ███╗██████╔╝███████║██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║\n  ██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║\n  ╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝\n   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ \n'
TAGLINE = '🐾 Digging up buried secrets - Automated OSINT Recon Tool'
GEO_API_URL = 'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
CRT_SH_URL = 'https://crt.sh/?q=%.{domain}&output=json'
WAYBACK_API_URL = 'https://archive.org/wayback/available?url={target}'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10'
OTX_DOMAIN_URL = 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
OTX_IP_URL = 'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
THREATFOX_API_URL = 'https://threatfox-api.abuse.ch/api/v1/'
HACKERTARGET_REVERSE_DNS = 'https://api.hackertarget.com/reversedns/?q={ip}'
HACKERTARGET_HTTP_HEADERS = 'https://api.hackertarget.com/httpheaders/?q={target}'
HACKERTARGET_PAGE_LINKS = 'https://api.hackertarget.com/pagelinks/?q={target}'
IPINFO_URL = 'https://ipinfo.io/{ip}/json'
SECURITYTRAILS_API_URL = 'https://api.securitytrails.com/v1/domain/{target}/subdomains?children_only=false&include_inactive=true'
HUNTER_API_URL = 'https://api.hunter.io/v2/domain-search?domain={target}&api_key={api_key}'
