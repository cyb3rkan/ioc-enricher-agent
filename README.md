<div align="center"> 
🔍 IOC Enricher Agent
 <img src="assets/banner.png" alt="IOC Enricher Banner" width="800"/> 

AI-Powered Indicator of Compromise (IOC) Enrichment Tool
Siber güvenlik analistlerinin manuel olarak yaptığı IOC zenginleştirme işlemlerini saniyeler içinde otomatize eden bir AI agent.
Features(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-features) • Installation(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-installation) • Usage(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-usage) • API Keys(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-api-keys) • Contributing(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-contributing)

 </div> 
🎯 Problem & Çözüm
❌ Geleneksel Yöntem
Bir SOC analisti şüpheli bir IP adresi gördüğünde, manuel olarak 5-6 farklı threat intelligence platformunu kontrol eder. Bu işlem her bir IOC için 10-15 dakika sürer.
✅ Bu Araç ile
Tek bir komutla tüm platformlardan veri toplanır, analiz edilir ve saniyeler içinde kapsamlı bir rapor oluşturulur.
⏱️ Geleneksel: 10-15 dakika/IOC
⚡ IOC Enricher: 5-10 saniye/IOC
📈 Verimlilik Artışı: %98+

✨ Features
 <table> <tr> <td width="50%"> 
🔎 Multi-Source Intelligence
* VirusTotal entegrasyonu
* AbuseIPDB reputation kontrolü
* Shodan port/servis bilgisi
* AlienVault OTX threat feeds
* GreyNoise classification
 </td> <td width="50%"> 
🤖 AI-Powered Analysis
* LLM ile tehdit özeti
* Risk skorlama algoritması
* Öneri ve aksiyon önerileri
* Bağlamsal analiz
 </td> </tr> <tr> <td width="50%"> 
📊 Reporting
* JSON/Markdown/HTML çıktı
* Görsel dashboard
* Export seçenekleri
* API endpoint desteği
 </td> <td width="50%"> 
⚡ Performance
* Asenkron API çağrıları
* Batch processing
* Caching mekanizması
* Rate limit yönetimi
 </td> </tr> </table> 
🏗️ Architecture
┌─────────────────────────────────────────────────────────────────┐
│                        IOC Enricher Agent                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  Input   │───▶│   Enricher   │───▶│    AI Analyzer       │  │
│  │  Parser  │    │    Engine    │    │    (LangChain)       │  │
│  └──────────┘    └──────────────┘    └──────────────────────┘  │
│       │                 │                       │               │
│       ▼                 ▼                       ▼               │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   IOC    │    │   External   │    │      Reporter        │  │
│  │Validator │    │    APIs      │    │   (JSON/MD/HTML)     │  │
│  └──────────┘    └──────────────┘    └──────────────────────┘  │
│                         │                                       │
│         ┌───────────────┼───────────────┐                      │
│         ▼               ▼               ▼                      │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐                  │
│   │VirusTotal│   │ AbuseIPDB│   │  Shodan  │   ...            │
│   └──────────┘   └──────────┘   └──────────┘                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

📦 Installation
Prerequisites
* Python 3.11 veya üzeri
* pip paket yöneticisi
* API anahtarları (aşağıya bakın)
Quick Start
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

🔑 API Keys
Bu araç aşağıdaki servislerin API anahtarlarını kullanır:
---------------------------------------------
| |Servis | |Gereklilik | |Ücretsiz Plan | |Kayıt Linki |
---------------------------------------------
| |VirusTotal | |⭐ Zorunlu | |✅ 500 req/gün | |virustotal.com(https://www.virustotal.com/gui/join-us) |
---------------------------------------------
| |AbuseIPDB | |⭐ Zorunlu | |✅ 1000 req/gün | |abuseipdb.com(https://www.abuseipdb.com/register) |
---------------------------------------------
| |Shodan | |📌 Önerilen | |✅ Sınırlı | |shodan.io(https://account.shodan.io/register) |
---------------------------------------------
| |OpenAI | |⭐ Zorunlu | |❌ Ücretli | |platform.openai.com(https://platform.openai.com/signup) |
---------------------------------------------
| |AlienVault OTX | |📌 Önerilen | |✅ Ücretsiz | |otx.alienvault.com(https://otx.alienvault.com/accounts/signup/) |
🚀 Usage
CLI Kullanımı
# Tek bir IP analizi
python ioc_enricher.py --ip 8.8.8.8

# Domain analizi
python ioc_enricher.py --domain malicious-site.com

# Hash analizi
python ioc_enricher.py --hash 44d88612fea8a8f36de82e1278abb02f

# Dosyadan toplu analiz
python ioc_enricher.py --file iocs.txt

# JSON çıktı
python ioc_enricher.py --ip 8.8.8.8 --output json

# Detaylı rapor
python ioc_enricher.py --ip 8.8.8.8 --verbose --report

Python API
from ioc_enricher import IOCEnricher

# Enricher'ı başlat
enricher = IOCEnricher()

# IP analizi
result = enricher.analyze_ip("185.220.101.1")
print(result.risk_score)  # 0-100 arası risk skoru
print(result.summary)     # AI tarafından oluşturulan özet
print(result.recommendations)  # Aksiyon önerileri

# Batch analizi
iocs = ["8.8.8.8", "malware.com", "abc123hash"]
results = enricher.analyze_batch(iocs)

Örnek Çıktı
╔══════════════════════════════════════════════════════════════════╗
║                    IOC ENRICHMENT REPORT                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: 185.220.101.1                                           ║
║  Type: IPv4 Address                                              ║
║  Analysis Date: 2024-01-15 14:32:00                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  🎯 RISK SCORE: 87/100 (HIGH)                                   ║
║  ████████████████████░░░░                                        ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  📊 INTELLIGENCE SOURCES                                         ║
║  ├─ VirusTotal: 12/89 engines flagged as malicious              ║
║  ├─ AbuseIPDB: Confidence Score 95%, 847 reports                ║
║  ├─ Shodan: Tor Exit Node, Ports: 22, 80, 443, 9001             ║
║  └─ OTX: Associated with 3 active threat campaigns              ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  🤖 AI ANALYSIS                                                  ║
║                                                                  ║
║  Bu IP adresi bilinen bir Tor çıkış noktasıdır ve birden        ║
║  fazla threat intelligence kaynağında kötü amaçlı aktivite      ║
║  ile ilişkilendirilmiştir. Son 30 günde brute-force ve          ║
║  web scanning aktivitesi raporlanmıştır.                        ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚡ RECOMMENDATIONS                                              ║
║  • Bu IP'yi firewall'da bloklayın                               ║
║  • İlgili sistemlerde log analizi yapın                         ║
║  • EDR/SIEM'de alert kuralı oluşturun                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

📁 Project Structure
ioc-enricher-agent/
├── 📂 src/
│   ├── 📄 __init__.py
│   ├── 📄 enricher.py        # Ana enrichment motoru
│   ├── 📄 analyzer.py        # AI analiz modülü
│   ├── 📄 reporter.py        # Rapor oluşturucu
│   └── 📂 providers/         # API entegrasyonları
│       ├── 📄 virustotal.py
│       ├── 📄 abuseipdb.py
│       ├── 📄 shodan.py
│       └── 📄 otx.py
├── 📂 tests/
│   ├── 📄 test_enricher.py
│   └── 📄 test_providers.py
├── 📂 assets/
│   ├── 🖼️ banner.png
│   └── 🎬 demo.gif
├── 📄 ioc_enricher.py        # CLI entry point
├── 📄 requirements.txt
├── 📄 .env.example
├── 📄 LICENSE
└── 📄 README.md

🛣️ Roadmap
* [x] Temel IOC parsing (IP, Domain, Hash)
* [x] VirusTotal entegrasyonu
* [x] AbuseIPDB entegrasyonu
* [ ] Shodan entegrasyonu
* [ ] AlienVault OTX entegrasyonu
* [ ] AI-powered analiz (LangChain)
* [ ] Web arayüzü (Streamlit)
* [ ] REST API endpoint
* [ ] Docker container
* [ ] Batch processing optimizasyonu
🤝 Contributing
Katkılarınızı bekliyoruz! Lütfen önce bir issue açarak neyi değiştirmek istediğinizi tartışalım.
# Fork'layın
# Feature branch oluşturun
git checkout -b feature/amazing-feature

# Değişikliklerinizi commit edin
git commit -m 'feat: add amazing feature'

# Branch'i push edin
git push origin feature/amazing-feature

# Pull Request açın

📜 License
Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için LICENSE(https://claude.ai/chat/LICENSE) dosyasına bakın.
⚠️ Disclaimer
Bu araç yalnızca eğitim ve yetkili güvenlik testi amaçlıdır. Yetkisiz sistemlerde kullanımı yasa dışıdır. Kullanıcılar, bu aracı kullanırken tüm geçerli yasalara uymakla yükümlüdür.
 <div align="center"> 
⬆ Başa Dön(https://claude.ai/chat/0fc71e36-eee4-4ef3-827b-8cff92baf87a#-ioc-enricher-agent)
Made with ❤️ by İSİM(https://github.com/cyb3rkan)

 </div>
