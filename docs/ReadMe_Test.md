# 🧪 Test Rehberi

## ⚡ Hızlı Test (1 Dakika)

Projenin çalışıp çalışmadığını test et:

```cmd
# Kapsamlı test scripti
python test_all.py
```

**Hepsi bu kadar!** Script otomatik olarak şunları test eder:
- ✅ API key'ler
- ✅ IOC validation
- ✅ Provider'lar
- ✅ AI analiz
- ✅ Raporlama
- ✅ Batch processing
- ✅ Error handling

---

## 📊 Beklenen Çıktı

```
======================================================================
  IOC ENRICHER AGENT - COMPREHENSIVE TEST SUITE
======================================================================

======================================================================
  TEST 1: Environment & Configuration
======================================================================

✅ [PASS] VirusTotal API Key
    └─ Configured
✅ [PASS] AbuseIPDB API Key
    └─ Configured
✅ [PASS] Shodan API Key
    └─ Configured
...

======================================================================
  TEST SUMMARY
======================================================================

Total Tests:    45
Passed:         43 ✅
Failed:         2 ❌
Pass Rate:      95.6%
Execution Time: 25.34s

🎉 EXCELLENT! All critical features working!
```

---

## 🎯 Test Kategorileri

### TEST 1: Environment & Configuration
- API key'lerin varlığı
- AI provider seçimi
- Klasör yapısı

### TEST 2: IOC Validation
- IP, Domain, Hash, URL, Email tespiti
- Defanging/sanitization
- Format validation

### TEST 3: Provider Connectivity
- VirusTotal bağlantısı
- AbuseIPDB bağlantısı
- Shodan bağlantısı
- OTX bağlantısı

### TEST 4: AI Analysis
- OpenAI/Gemini connection
- Risk scoring
- Summary generation
- Recommendations

### TEST 5: Report Generation
- Terminal format
- JSON format
- Markdown format

### TEST 6: Full Enrichment Flow
- Safe IP (8.8.8.8)
- Safe Domain (google.com)
- Test Hash (EICAR)

### TEST 7: Batch Processing
- Multiple IOCs
- Parallel processing
- Result aggregation

### TEST 8: Error Handling
- Invalid IOCs
- Empty input
- Edge cases

---

## 🔍 Manuel Test Komutları

Belirli özellikleri manuel test etmek için:

### Provider Durumu
```cmd
python main.py --status
```

### Tek IOC
```cmd
python main.py --ip 8.8.8.8
python main.py --domain google.com
python main.py --hash 44d88612fea8a8f36de82e1278abb02f
```

### Farklı Formatlar
```cmd
# JSON
python main.py --ip 1.1.1.1 --format json

# Markdown
python main.py --domain example.com --format markdown

# Dosyaya kaydet
python main.py --ip 8.8.8.8 --format json --save
```

### Batch Processing
```cmd
python main.py --file example_iocs.txt
```

---


## 📈 Pass Rate Rehberi

| Pass Rate | Durum | Açıklama |
|-----------|-------|----------|
| **90-100%** | 🎉 Mükemmel | Tüm özellikler çalışıyor |
| **70-89%** | ✅ İyi | Bazı küçük sorunlar var |
| **50-69%** | ⚠️ Uyarı | Önemli sorunlar var |
| **0-49%** | ❌ Kritik | Büyük sorunlar var |

---

## 🚀 İlk Kez Test Eden İçin

```cmd
# 1. Test scriptini çalıştır
python test_all.py

# 2. Çıktıya bak:
#    - Yeşil ✅ : Çalışıyor
#    - Kırmızı ❌ : Sorun var

# 3. Sorun varsa:
#    - API key'leri kontrol et (.env)
#    - pip install -r requirements.txt
#    - Tekrar test et
```

---

## ✅ Test Tamamlandıktan Sonra

Test başarılıysa:
1. ✅ Gerçek IOC'lerle dene
2. ✅ Batch analiz yap
3. ✅ Farklı formatları test et
4. ✅ Projeyi GitHub'a yükle
5. ✅ Staj başvurularında kullan!

---

**Mutlu testler! 🧪**
