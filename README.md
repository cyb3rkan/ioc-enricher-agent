# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In_Development-yellow?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

**AI-Powered Indicator of Compromise (IOC) Enrichment Tool**

Siber güvenlik analistlerinin manuel olarak yaptığı IOC zenginleştirme işlemlerini saniyeler içinde otomatize eden bir AI agent.

---

## 🎯 Problem ve Çözüm

### ❌ Geleneksel Yöntem
Bir SOC analisti şüpheli bir IP adresi gördüğünde, manuel olarak 5-6 farklı threat intelligence platformunu kontrol eder. Bu işlem her bir IOC için **10-15 dakika** sürer.

### ✅ Bu Araç ile
Tek bir komutla tüm platformlardan veri toplanır, analiz edilir ve saniyeler içinde kapsamlı bir rapor oluşturulur.

| Metrik | Değer |
|--------|-------|
| ⏱️ Geleneksel | 10-15 dakika/IOC |
| ⚡ IOC Enricher | 5-10 saniye/IOC |
| 📈 Verimlilik Artışı | %98+ |

---

## ✨ Özellikler

### 🔎 Multi-Source Intelligence
- VirusTotal entegrasyonu
- AbuseIPDB reputation kontrolü
- Shodan port/servis bilgisi
- AlienVault OTX threat feeds
- GreyNoise classification

### 🤖 AI-Powered Analysis
- LLM ile tehdit özeti oluşturma
- Risk skorlama algoritması
- Öneri ve aksiyon önerileri
- Bağlamsal analiz

### 📊 Reporting
- JSON/Markdown/HTML çıktı formatları
- Görsel dashboard
- Export seçenekleri
- API endpoint desteği

### ⚡ Performance
- Asenkron API çağrıları
- Batch processing desteği
- Caching mekanizması
- Rate limit yönetimi

---

## 📦 Kurulum

### Gereksinimler

- Python 3.11 veya üzeri
- pip paket yöneticisi
- API anahtarları (aşağıya bakın)

### Hızlı Başlangıç

```bash
# Repository'yi klonla
git clone https://github.com/cyb3rkan/ioc-enricher-agent.git
cd ioc-enricher-agent

# Virtual environment oluştur
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Bağımlılıkları yükle
pip install -r requirements.txt

# Environment değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle ve API key'lerini ekle
```

---

## 🔑 API Anahtarları

Bu araç aşağıdaki servislerin API anahtarlarını kullanır:

| Servis | Gereklilik | Ücretsiz Plan | Kayıt Linki |
|--------|------------|---------------|-------------|
| VirusTotal | ⭐ Zorunlu | ✅ 500 req/gün | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ⭐ Zorunlu | ✅ 1000 req/gün | [abuseipdb.com](https://www.abuseipdb.com/register) |
| Shodan | 📌 Önerilen | ✅ Sınırlı | [shodan.io](https://account.shodan.io/register) |
| OpenAI | ⭐ Zorunlu | ❌ Ücretli | [platform.openai.com](https://platform.openai.com/signup) |
| AlienVault OTX | 📌 Önerilen | ✅ Ücretsiz | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup/) |

---

## 🚀 Kullanım

### CLI Kullanımı

```bash
# Tek bir IP analizi
python ioc_enricher.py --ip 8.8.8.8

# Domain analizi
python ioc_enricher.py --domain malicious-site.com

# Hash analizi
python ioc_enricher.py --hash 44d88612fea8a8f36de82e1278abb02f

# Dosyadan toplu analiz
python ioc_enricher.py --file iocs.txt

# JSON çıktı formatı
python ioc_enricher.py --ip 8.8.8.8 --output json
```

### Python API

```python
from ioc_enricher import IOCEnricher

# Enricher'ı başlat
enricher = IOCEnricher()

# IP analizi
result = enricher.analyze_ip("185.220.101.1")
print(result.risk_score)       # 0-100 arası risk skoru
print(result.summary)          # AI tarafından oluşturulan özet
print(result.recommendations)  # Aksiyon önerileri
```

### Örnek Çıktı

```
╔══════════════════════════════════════════════════════════════════╗
║                    IOC ENRICHMENT REPORT                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: 185.220.101.1                                           ║
║  Type: IPv4 Address                                              ║
║  Analysis Date: 2024-01-15 14:32:00                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  🎯 RISK SCORE: 87/100 (HIGH)                                   ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  📊 INTELLIGENCE SOURCES                                         ║
║  • VirusTotal: 12/89 engines flagged as malicious               ║
║  • AbuseIPDB: Confidence Score 95%, 847 reports                 ║
║  • Shodan: Tor Exit Node, Ports: 22, 80, 443, 9001              ║
║  • OTX: Associated with 3 active threat campaigns               ║
╠══════════════════════════════════════════════════════════════════╣
║  🤖 AI ANALYSIS                                                  ║
║                                                                  ║
║  Bu IP adresi bilinen bir Tor çıkış noktasıdır ve birden        ║
║  fazla threat intelligence kaynağında kötü amaçlı aktivite      ║
║  ile ilişkilendirilmiştir.                                      ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚡ RECOMMENDATIONS                                              ║
║  • Bu IP'yi firewall'da bloklayın                               ║
║  • İlgili sistemlerde log analizi yapın                         ║
║  • EDR/SIEM'de alert kuralı oluşturun                          ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 📁 Proje Yapısı

```
ioc-enricher-agent/
├── src/
│   ├── __init__.py
│   ├── enricher.py        # Ana enrichment motoru
│   ├── analyzer.py        # AI analiz modülü
│   ├── reporter.py        # Rapor oluşturucu
│   └── providers/         # API entegrasyonları
│       ├── virustotal.py
│       ├── abuseipdb.py
│       ├── shodan.py
│       └── otx.py
├── tests/
│   ├── test_enricher.py
│   └── test_providers.py
├── ioc_enricher.py        # CLI entry point
├── requirements.txt
├── .env.example
├── LICENSE
└── README.md
```

---

## 🛣️ Yol Haritası

- [x] Temel IOC parsing (IP, Domain, Hash)
- [x] VirusTotal entegrasyonu
- [x] AbuseIPDB entegrasyonu
- [ ] Shodan entegrasyonu
- [ ] AlienVault OTX entegrasyonu
- [ ] AI-powered analiz (LangChain)
- [ ] Web arayüzü (Streamlit)
- [ ] REST API endpoint
- [ ] Docker container
- [ ] Batch processing optimizasyonu

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen önce bir issue açarak neyi değiştirmek istediğinizi tartışalım.

```bash
# Fork'layın ve klonlayın
git clone https://github.com/YOUR_USERNAME/ioc-enricher-agent.git

# Feature branch oluşturun
git checkout -b feature/amazing-feature

# Değişikliklerinizi commit edin
git commit -m 'feat: add amazing feature'

# Branch'i push edin
git push origin feature/amazing-feature

# Pull Request açın
```

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca eğitim ve yetkili güvenlik testi amaçlıdır**. Yetkisiz sistemlerde kullanımı yasa dışıdır. Kullanıcılar, bu aracı kullanırken tüm geçerli yasalara uymakla yükümlüdür.

---

## 📫 İletişim

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/erkansahin23/)

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**
