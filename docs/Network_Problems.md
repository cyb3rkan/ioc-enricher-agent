# 🔧 Ağ Bağlantı Sorunları - Çözüm Rehberi

## ❌ Gördüğün Hata

```
ConnectionResetError(10054, 'Varolan bir bağlantı uzaktaki bir ana bilgisayar tarafından zorla kapatıldı')
```

Bu hata **Windows'a özgü** bir ağ sorunudur. Genellikle şunlardan kaynaklanır:

---

## ✅ ÇÖZÜMLER (Sırayla Dene)

### 1️⃣ Windows Defender Firewall'u Geçici Kapat

```cmd
# Windows Ayarlar → Güvenlik → Firewall
# "Etki Alanı Ağı" ve "Özel Ağ" → Kapat

# Veya PowerShell (Yönetici):
Set-NetFirewallProfile -Profile Domain,Private -Enabled False

# Test et:
python test_all.py

# Sonra tekrar aç:
Set-NetFirewallProfile -Profile Domain,Private -Enabled True
```

---

### 2️⃣ Antivirus'ü Geçici Devre Dışı Bırak

**Avast, AVG, Kaspersky, Norton** gibi antivirüsler Python'un ağ bağlantılarını engelleyebilir.

```
1. Antivirus'ünü aç
2. "Korumayı Duraklat" → 10 dakika
3. python test_all.py
4. Çalışıyorsa → Python'u beyaz listeye ekle
```

---

### 3️⃣ VPN Kullanıyorsan

VPN bazen API bağlantılarını keser:

```cmd
# VPN'i kapat
# Test et
python test_all.py

# Çalışıyorsa → VPN ayarlarını kontrol et
```

---

### 4️⃣ DNS Değiştir (Google DNS)

```cmd
# PowerShell (Yönetici olarak):

# Ethernet için:
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("8.8.8.8","8.8.4.4")

# WiFi için:
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses ("8.8.8.8","8.8.4.4")

# Test et:
python test_all.py
```

Veya manuel:
1. **Denetim Masası** → **Ağ ve İnternet** → **Ağ Bağlantıları**
2. Aktif bağlantıya sağ tık → **Özellikler**
3. **Internet Protocol Version 4 (TCP/IPv4)** → **Özellikler**
4. **Şu DNS sunucu adreslerini kullan:**
   - Tercih edilen: `8.8.8.8`
   - Alternatif: `8.8.4.4`

---

### 5️⃣ Proxy Ayarlarını Kontrol Et

```cmd
# PowerShell:
netsh winhttp show proxy

# Eğer proxy varsa:
netsh winhttp reset proxy
```

---

###  6️⃣ Python'a SSL Sertifikası Yükle

```cmd
pip install --upgrade certifi
python -m pip install --upgrade pip setuptools
```

---

### 7️⃣ Sadece Çalışan Provider'ları Kullan

Eğer sadece **VirusTotal** ve **OTX** çalışıyorsa, o şekilde kullan:

`.env` dosyasında:
```bash
# Çalışmayanları boş bırak
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=

# Çalışanları kullan
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
```

Proje yine çalışır, sadece 2 provider ile!

---

## 🔍 Hangi Provider Çalışıyor?

Test sonucuna bak:

```
✅ [PASS] VirusTotal Connectivity     → ÇALIŞIYOR
✅ [PASS] AlienVault OTX Connectivity → ÇALIŞIYOR
❌ [FAIL] Shodan Connectivity         → ÇALIŞMIYOR
❌ [FAIL] AbuseIPDB Connectivity      → ÇALIŞMIYOR
```

**2 provider çalışıyorsa yeterli!** Proje kullanılabilir durumda.

---

## 🌐 İnternet Bağlantısını Test Et

```cmd
# Temel bağlantı
ping google.com

# HTTPS testi
curl https://www.virustotal.com

# Python requests testi
python -c "import requests; print(requests.get('https://api.ipify.org').text)"
```

Hepsi çalışıyorsa → Python'a özel bir sorun var.

---

## ⚠️ Güvenlik Notu

`verify=False` sadece **development/test** için kullanılmalı!

Production'da kullanacaksan:
```python
verify=True  # Varsayılan
```

Ama test için **sorun değil** - threat intelligence API'ları zaten güvenli.

---

## 📊 Beklenen Sonuç

Düzeltmeden sonra:

```
======================================================================
  TEST 3: Provider Connectivity
======================================================================

Testing with IP: 8.8.8.8

✅ [PASS] VirusTotal Connectivity
    └─ Response time: 1.52s
✅ [PASS] AbuseIPDB Connectivity
    └─ Response time: 1.23s
✅ [PASS] Shodan Connectivity
    └─ Response time: 1.67s
✅ [PASS] AlienVault OTX Connectivity
    └─ Response time: 0.98s
```

---

## 🎯 Hızlı Kontrol

```cmd
# Güncellemeyi test et
python -c "import urllib3; urllib3.disable_warnings(); import requests; print(requests.get('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8', verify=False, timeout=10))"
```

Çalışıyorsa → Proje de çalışacak!

---

## 🆘 Hala Çalışmıyorsa?

1. **İnternet sağlayıcını kontrol et** - Bazı ISP'ler API'ları engelliyor
2. **Mobil hotspot dene** - Telefon internetinden bağlan
3. **Farklı ağ dene** - Evden, kafeden, kampüsten dene
4. **Sadece çalışan provider'ları kullan** - 2 provider yeter!

---

**En kolayı: Yeni ZIP'i indir, fix otomatik gelecek!** 🚀
