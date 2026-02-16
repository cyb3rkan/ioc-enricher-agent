# 🚀 Hızlı Başlangıç Kılavuzu

## ⏱️ 5 Dakikada Başla

### Adım 1: Bağımlılıkları Yükle (1 dakika)

```bash
# Virtual environment oluştur (opsiyonel ama önerilen)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

### Adım 2: API Anahtarlarını Ekle (2 dakika)

`.env` dosyasını aç ve şu satırları doldur:

```bash
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY=YOUR_ABUSEIPDB_API_KEY
SHODAN_API_KEY=YOUR_SHODAN_API_KEY
OTX_API_KEY=YOUR_OTX_API_KEY
OPENAI_API_KEY=YOUR_OPENAI_API_KEY
```

**Not:** API key'ler zaten .env dosyasında mevcut!

### Adım 3: Test Et (2 dakika)

```bash
# Provider durumunu kontrol et
python main.py --status

# İlk IP analizini yap
python main.py --ip 8.8.8.8

# Domain analizi
python main.py --domain google.com

# Batch test
python main.py --file example_iocs.txt
```

## 📋 Temel Komutlar

```bash
# Tek IOC analizi
python main.py --ip 1.1.1.1
python main.py --domain example.com
python main.py --hash 44d88612fea8a8f36de82e1278abb02f
python main.py --url http://example.com

# Otomatik tip tespiti
python main.py --ioc 192.168.1.1

# JSON çıktı
python main.py --ip 8.8.8.8 --format json

# Rapor kaydet
python main.py --ip 8.8.8.8 --format markdown --save

# Dosyadan toplu analiz
python main.py --file example_iocs.txt
```

## 🎯 İlk Hedefler

1. ✅ Projeyi çalıştır
2. ✅ Google DNS'i (8.8.8.8) analiz et
3. ✅ Kendi domainini test et
4. ✅ Batch analiz yap
5. ✅ JSON rapor oluştur

## 📚 Sonraki Adımlar

1. **ReadMe.md** oku - Detaylı dokümantasyon
2. Kendi IOC'lerini test et
3. Raporları incele
4. Projeyi özelleştir

## 💡 İpuçları

- `--help` parametresi ile tüm seçenekleri gör
- `--no-banner` ile banner'ı gizle
- `--format json` ile programatik kullanım
- `example_iocs.txt` dosyasını düzenle ve test et

## 🎉 Hazırsın!

Artık IOC Enricher Agent'ı kullanmaya hazırsın. Mutlu analizler! 🚀
