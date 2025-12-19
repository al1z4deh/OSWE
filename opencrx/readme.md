# OpenCRX Tam İstismar Bələdçisi
## OSWE Sertifikat Hazırlığı üçün Azərbaycanca Tam Təlimat

```
📋 Mündəricat

Modulun Ümumi Baxışı
Laboratoriya Mühitinin Qurulması
Faza 1: Kəşfiyyat
Faza 2: Parol Sıfırlama Zəifliyi
Faza 3: XXE İstismarı
Faza 4: HSQLDB Girişi
Faza 5: RCE Java Dil Rutinləri vasitəsilə
POC Skriptlər
```
```
Modulun Ümumi Baxışı
Hədəf Tətbiq: openCRX CRM Sistemi
Texnologiyalar: Java, Apache TomEE, HSQLDB
Hücum Zənciri:
Parol Sıfırlama Bypass → Təsdiqlənmiş Giriş → XXE → DB Etimadnamələri → Fayl Yazma → RCE
Zəiflik Xülasəsi
ZəiflikTəsirCVE NövüParol Sıfırlama Token BypassHesab Ələ KeçirməAuth BypassXML Xarici Obyekt (XXE)Fayl OxumaInformation DisclosureHSQLDB Açıq PortDB GirişiMisconfigurationJava Language RoutinesFayl YazmaCode InjectionJSP Upload & ExecutionRCERemote Code Execution

Laboratoriya Mühitinin Qurulması
```
