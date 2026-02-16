# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

**AI-Powered Indicator of Compromise (IOC) Enrichment Tool**

Siber güvenlik analistlerinin manuel olarak yaptığı IOC zenginleştirme işlemlerini saniyeler içinde otomatize eden bir AI agent.

---

## 🎯 Problem ve Çözüm

### ❌ Geleneksel Yöntem
Bir SOC analisti şüpheli bir IP adresi gördüğünde, manuel olarak 5-6 farklı threat intelligence platformunu kontrol eder. Bu işlem her bir IOC için **10-15 dakika** sürer.

### ✅ Bu Araç ile
Tek bir komutla tüm platformlardan veri toplanır, analiz edilir ve saniyeler içinde kapsamlı bir rapor oluşturulur.

| Metrik | Değer            |
|--------|------------------|
| ⏱️ Geleneksel | 10-15 dakika/IOC |
| ⚡ IOC Enricher | 5-10 saniye/IOC  |
| 📈 Verimlilik Artışı | %90+             |

---

## ✨ Özellikler

### 🔎 Multi-Source Intelligence
- ✅ VirusTotal entegrasyonu
- ✅ AbuseIPDB reputation kontrolü
- ✅ Shodan port/servis bilgisi
- ✅ AlienVault OTX threat feeds

### 🤖 AI-Powered Analysis
- OpenAI GPT-4 ile akıllı tehdit analizi
- Risk skorlama (0-100)
- Türkçe/İngilizce özetler
- Otomatik öneri sistemi
- Güven skoru hesaplama

### 📊 Reporting
- Terminal (renkli çıktı)
- JSON export
- Markdown raporlar
- Dosya kaydetme

### ⚡ Performance
- Paralel API çağrıları
- Batch processing desteği
- Hata yönetimi
- Rate limit uyumlu

---

## 📦 Kurulum

### Gereksinimler

- Python 3.11 veya üzeri
- pip paket yöneticisi
- API anahtarları (aşağıya bakın)

### Hızlı Başlangıç

```bash
# 1. Projeyi indir
# (GitHub'a yükledikten sonra: git clone https://github.com/cyb3rkan/ioc-enricher-agent.git)

# 2. Proje dizinine gir
cd ioc-enricher-agent

# 3. Virtual environment oluştur (önerilen)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# 4. Bağımlılıkları yükle
pip install -r requirements.txt

# 5. .env dosyasını düzenle
# .env dosyasını açıp API key'lerini ekle

# 6. Test et
python main.py --status
```

---

## 🔑 API Anahtarları

### Gerekli API Key'ler

Bu araç aşağıdaki servislerin API anahtarlarını kullanır. `.env` dosyasına ekleyin:

| Servis | Gereklilik | Ücretsiz Plan | Kayıt Linki |
|--------|------------|---------------|-------------|
| VirusTotal | ⭐ Zorunlu | ✅ 500 req/gün | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ⭐ Zorunlu | ✅ 1000 req/gün | [abuseipdb.com](https://www.abuseipdb.com/register) |
| OpenAI | ⭐ Zorunlu | ✅ $5 ücretsiz | [platform.openai.com](https://platform.openai.com/signup) |
| Shodan | 📌 Önerilen | ✅ 100 req/ay | [shodan.io](https://account.shodan.io/register) |
| AlienVault OTX | 📌 Önerilen | ✅ Sınırsız | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup/) |

### .env Dosyası Yapılandırması

```bash
# .env dosyasını düzenle
VIRUSTOTAL_API_KEY=//your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
OTX_API_KEY=your_otx_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

---

## 🚀 Kullanım

### Temel Kullanım

```bash
# IP adresi analizi
python main.py --ip 8.8.8.8

# Domain analizi
python main.py --domain malicious-site.com

# Hash analizi
python main.py --hash 44d88612fea8a8f36de82e1278abb02f

# URL analizi
python main.py --url http://malicious-site.com/malware.exe

# Otomatik tip tespiti
python main.py --ioc 192.168.1.1
```

### İleri Seviye Kullanım

```bash
# JSON formatında çıktı
python main.py --ip 8.8.8.8 --format json

# Markdown rapor oluştur ve kaydet
python main.py --domain example.com --format markdown --save

# Dosyadan toplu analiz
python main.py --file example_iocs.txt

# Provider durumunu kontrol et
python main.py --status
```

### Örnek Çıktı

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║         🔍 IOC ENRICHER AGENT - AI-Powered Analysis             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

🔍 Analyzing IPV4: 8.8.8.8
📡 Querying 4 threat intelligence providers...

  ✓ VirusTotal: success
  ✓ AbuseIPDB: success
  ✓ Shodan: success
  ✓ AlienVault OTX: success

🤖 Performing AI analysis...

════════════════════════════════════════════════════════════════════
🔍 IOC ENRİCHMENT RAPORU
════════════════════════════════════════════════════════════════════

Target: 8.8.8.8
Type: IPV4
Date: 2024-01-15 14:32:00
Confidence: 100%

────────────────────────────────────────────────────────────────────
🎯 RISK SCORE: 5/100 ✅ LOW
────────────────────────────────────────────────────────────────────

📊 THREAT INTELLIGENCE SOURCES
────────────────────────────────────────────────────────────────────

✓ VirusTotal
  └─ Detection: 0 malicious, 0 suspicious / 89 engines

✓ AbuseIPDB
  └─ Confidence Score: 0%, Total Reports: 0

✓ Shodan
  └─ Open Ports: 53, 443
  └─ Organization: Google LLC

✓ AlienVault OTX
  └─ Threat Pulses: 0

────────────────────────────────────────────────────────────────────

🤖 AI ANALİZİ
────────────────────────────────────────────────────────────────────

Türkçe Özet:
Bu IP adresi Google'ın genel DNS sunucusudur. Hiçbir tehdit 
istihbaratı kaynağında kötü amaçlı aktivite tespit edilmemiştir.

Önemli Bulgular:
  • Tüm antivirüs motorları temiz olarak değerlendirdi
  • Hiçbir abuse raporu yok
  • Google LLC'ye ait yasal bir servis

⚡ ÖNERİLER
  • Bu IP güvenlidir, aksiyon gerekmez
  • Normal DNS trafiği olarak değerlendirin

Tags: dns, google, safe, public-service

════════════════════════════════════════════════════════════════════

⏱️  Execution time: 3.45s
```

---

## 📁 Proje Yapısı

```
ioc-enricher-agent/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── config.py            # Configuration management
│   ├── validators.py        # IOC validation
│   ├── enricher.py          # Main orchestrator
│   ├── analyzer.py          # AI analysis engine
│   ├── reporter.py          # Report generator
│   └── providers/           # API integrations
│       ├── __init__.py
│       ├── base.py          # Base provider class
│       ├── virustotal.py    # VirusTotal integration
│       ├── abuseipdb.py     # AbuseIPDB integration
│       ├── shodan.py        # Shodan integration
│       └── otx.py           # AlienVault OTX integration
├── tests/
│   └── __init__.py          # Unit tests
├── data/
│   └── cache/               # API response cache
├── reports/                 # Generated reports
├── logs/                    # Application logs
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
├── .env                     # API keys (GİZLİ - Git'e eklenmez)
├── .env.example             # Environment template
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🧪 Test

```bash
# Unit testleri çalıştır
python -m pytest tests/ -v

# Coverage raporu
python -m pytest tests/ --cov=src --cov-report=html

# Örnek IOC'leri test et
python main.py --file example_iocs.txt
```

---

## 🔒 Güvenlik


- 🔐 API key'lerinizi kimseyle paylaşmayın
- 📝 Rate limit'lere uyun
- ✅ Sadece yetkili sistemlerde kullanın

---

## 📈 Performans İpuçları

1. **Batch Processing**: Çok sayıda IOC için `--file` kullanın
2. **Cache**: Tekrar eden sorgular otomatik önbelleklenir
3. **Parallel Queries**: Provider'lar paralel çalışır
4. **Rate Limiting**: Otomatik hız sınırlama yönetimi

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'feat: add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca eğitim ve yetkili güvenlik testi amaçlıdır**. Yetkisiz sistemlerde kullanımı yasa dışıdır. Kullanıcılar, bu aracı kullanırken tüm geçerli yasalara uymakla yükümlüdür.

---

## 📫 İletişim

**Erkan Şahin**
- LinkedIn: [erkansahin23](https://www.linkedin.com/in/erkansahin23/)
- GitHub: [@cyb3rkan](https://github.com/cyb3rkan)

---

## 🙏 Teşekkürler

Bu proje aşağıdaki harika servisler sayesinde mümkün:
- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
- [Shodan](https://www.shodan.io)
- [AlienVault OTX](https://otx.alienvault.com)
- [OpenAI](https://openai.com)

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**
