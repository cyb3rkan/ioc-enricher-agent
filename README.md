# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production-brightgreen?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

**AI-Powered Threat Intelligence Aggregation & Analysis Tool**

A professional cybersecurity tool that aggregates data from multiple threat intelligence providers and uses AI to perform comprehensive Indicator of Compromise (IOC) analysis.

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

## 📊 Hızlı İstatistikler

- **3,000+ Satır Kod**
- **15 Python Modülü**
- **42 Test Durumu**
- **7 API Entegrasyonu**
- **%95+ Test Başarı Oranı**

---

## ✨ Özellikler

### 🔎 Multi-Source Intelligence
- **VirusTotal**: Dosya ve URL analizi
- **AbuseIPDB**: IP reputation kontrolü
- **Shodan**: Port/servis bilgisi
- **AlienVault OTX**: Threat feeds
- **GreyNoise**: Classification

### 🤖 AI-Powered Analysis
- **OpenAI GPT** veya **Google Gemini** ile tehdit analizi
- Otomatik risk skorlama (0-100)
- Severity sınıflandırması (LOW/MEDIUM/HIGH/CRITICAL)
- Türkçe ve İngilizce özetler
- Aksiyon önerileri

### 📊 Multi-Format Reporting
- Renkli terminal çıktısı
- JSON export
- Markdown raporları
- HTML dashboard (yakında)

### ⚡ Performance
- Asenkron API çağrıları
- Batch processing desteği
- Resilient architecture (provider fail-safe)
- Paralel IOC analizi

### 🔎 Desteklenen IOC Tipleri
- IPv4 & IPv6 adresleri
- Domain isimleri
- URL'ler
- File hash'ler (MD5, SHA1, SHA256)
- Email adresleri

---

## 🚀 Kurulum

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

# Virtual environment'ı aktifleştir
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

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
| AlienVault OTX | 📌 Önerilen | ✅ Ücretsiz | [otx.alienvault.com](https://otx.alienvault.com/api) |
| OpenAI | ⭐ Zorunlu* | ❌ Ücretli | [platform.openai.com](https://platform.openai.com/signup) |
| Google Gemini | ⭐ Zorunlu* | ✅ Ücretsiz | [aistudio.google.com](https://aistudio.google.com/app/apikey) |

*OpenAI veya Gemini'den birini seçmeniz yeterli

### Configuration

`.env` dosyanıza API anahtarlarınızı ekleyin:

```bash
# Threat Intelligence Providers
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here

# AI Provider (birini seçin)
AI_PROVIDER=openai  # veya gemini
OPENAI_API_KEY=your_key_here  # OpenAI kullanıyorsanız
GEMINI_API_KEY=your_key_here  # Gemini kullanıyorsanız
```

---

## 💻 Kullanım

### CLI Kullanımı

```bash
# Provider durumunu kontrol et
python main.py --status

# Tek bir IP analizi
python main.py --ip 8.8.8.8

# Domain analizi
python main.py --domain malicious-site.com

# Hash analizi
python main.py --hash 44d88612fea8a8f36de82e1278abb02f

# IOC tipini otomatik algıla
python main.py --ioc 1.1.1.1

# Dosyadan toplu analiz
python main.py --file example_iocs.txt

# JSON formatında kaydet
python main.py --ip 8.8.8.8 --format json --save

# Markdown rapor oluştur
python main.py --ip 8.8.8.8 --format markdown --save
```

### Python API

```python
from src.enricher import IOCEnricher

# Enricher'ı başlat
enricher = IOCEnricher()

# IP analizi
result = enricher.analyze_ip("185.220.101.1")
print(result.risk_score)       # 0-100 arası risk skoru
print(result.summary)          # AI tarafından oluşturulan özet
print(result.recommendations)  # Aksiyon önerileri

# Batch processing
iocs = ["8.8.8.8", "1.1.1.1", "malicious.com"]
results = enricher.analyze_batch(iocs)
```

---

## 📊 Örnek Çıktı

```
╔══════════════════════════════════════════════════════════════════╗
║                    IOC ENRICHMENT REPORT                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: 185.220.101.1                                           ║
║  Type: IPv4 Address                                              ║
║  Analysis Date: 2024-02-17 14:32:00                              ║
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
║  ile ilişkilendirilmiştir. Yüksek risk seviyesi nedeniyle       ║
║  acil aksiyon gerektirir.                                       ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚡ RECOMMENDATIONS                                              ║
║  • Bu IP'yi firewall'da bloklayın                               ║
║  • İlgili sistemlerde log analizi yapın                         ║
║  • EDR/SIEM'de alert kuralı oluşturun                          ║
║  • Incident response prosedürünü başlatın                       ║
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
│   ├── config.py          # Configuration yönetimi
│   ├── validators.py      # IOC validation
│   └── providers/         # API entegrasyonları
│       ├── __init__.py
│       ├── base.py
│       ├── virustotal.py
│       ├── abuseipdb.py
│       ├── shodan.py
│       └── otx.py
├── tests/
│   ├── __init__.py
│   ├── test_enricher.py
│   ├── test_analyzer.py
│   └── test_providers.py
├── data/
│   └── cache/
├── docs/
│   ├── Quick_Start.md
│   ├── ReadMe_Test.md
│   ├── ReadMe_Main.md
│   └── Network_Problems.md
├── logs/
├── reports/
├── main.py                # CLI entry point
├── test_all.py            # Test suite runner
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## 📖 Dokümantasyon

- [**Quick Start Guide**](docs/Quick_Start.md) - 5 dakikada başla
- [**Testing Guide**](docs/ReadMe_Test.md) - Kapsamlı test dokümantasyonu
- [**Network Troubleshooting**](docs/Network_Problems.md) - Bağlantı sorunlarını çöz
- [**Main Documentation**](docs/ReadMe_Main.md) - Detaylı özellik dokümantasyonu

---

## 🧪 Testing

Kapsamlı test suite'ini çalıştırın:

```bash
# Tüm testleri çalıştır
python test_all.py

# Sadece unit testler
pytest tests/test_enricher.py

# Coverage raporu ile
pytest --cov=src tests/
```

Beklenen sonuç:
```
Total Tests: 42
Passed: 40+ ✅
Pass Rate: 95%+
```

---

## 🛡️ Güvenlik

- API anahtarları `.env` dosyasında güvenli şekilde saklanır (git-ignored)
- Veri persistence yok (privacy-first)
- Timeout protection
- Rate limiting desteği
- Error handling ve fallback mekanizmaları
- No data logging

---

## 🛣️ Yol Haritası

- [x] Temel IOC parsing (IP, Domain, Hash)
- [x] VirusTotal entegrasyonu
- [x] AbuseIPDB entegrasyonu
- [x] Shodan entegrasyonu
- [x] AlienVault OTX entegrasyonu
- [x] AI-powered analiz (OpenAI & Gemini)
- [x] Batch processing
- [x] Multi-format reporting
- [ ] Web arayüzü (Streamlit)
- [ ] REST API endpoint
- [ ] Docker container
- [ ] CI/CD pipeline
- [ ] GreyNoise entegrasyonu
- [ ] Dashboard visualizations

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

### Contribution Guidelines

1. Kod standardına uyun (PEP 8)
2. Test coverage'ı koruyun (%90+)
3. Dokümantasyon güncelleyin
4. Commit mesajlarında conventional commits kullanın

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca eğitim ve yetkili güvenlik testi amaçlıdır**. Yetkisiz sistemlerde kullanımı yasa dışıdır. Kullanıcılar, bu aracı kullanırken tüm geçerli yasalara uymakla yükümlüdür.

**Bu araç:**
- Yalnızca meşru güvenlik araştırmaları için tasarlanmıştır
- Kötü amaçlı kullanım için tasarlanmamıştır
- Kullanıcının sorumluluğundadır

---

## 🙏 Teşekkürler

- VirusTotal - Kapsamlı malware detection için
- AbuseIPDB - IP reputation verisi için
- Shodan - Infrastructure intelligence için
- AlienVault OTX - Threat pulse data için
- OpenAI & Google - AI analiz yetenekleri için

---

## 📧 İletişim

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/erkansahin23/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cyb3rkan)

Sorular, sorunlar veya öneriler için lütfen GitHub'da bir issue açın.

---

## ⭐ Star History

Bu projeyi faydalı bulduysanız, lütfen yıldız vermeyi düşünün!

[![Star History Chart](https://api.star-history.com/svg?repos=cyb3rkan/ioc-enricher-agent&type=Date)](https://star-history.com/#cyb3rkan/ioc-enricher-agent&Date)

---

**Built with ❤️ for the cybersecurity community**

*Making threat intelligence accessible to everyone*
