# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

**AI-Powered Threat Intelligence Aggregation & Analysis Tool**

A professional cybersecurity tool that aggregates data from multiple threat intelligence providers and uses AI to perform comprehensive Indicator of Compromise (IOC) analysis.

---

## 🎯 Problem Statement & Solution

### ❌ Traditional Method
When a SOC analyst encounters a suspicious IP address, they must manually check 5-6 different threat intelligence platforms. This process takes **10-15 minutes per IOC**.

### ✅ With This Tool
A single command collects data from all platforms, analyzes it, and generates a comprehensive report in seconds.

| Metric | Value |
|--------|-------|
| ⏱️ Traditional Method | 10-15 minutes/IOC |
| ⚡ IOC Enricher | 5-10 seconds/IOC |
| 📈 Efficiency Gain | 98%+ |

---

## 📊 Project Statistics

| Category | Details |
|----------|---------|
| 📝 Lines of Code | 3,000+ |
| 🐍 Python Modules | 15 |
| 🧪 Test Cases | 42 |
| 🔌 API Integrations | 7 |
| ✅ Test Pass Rate | 95%+ |

---

## ✨ Features

### 🔎 Multi-Source Intelligence

| Provider | Capability |
|----------|------------|
| **VirusTotal** | File and URL analysis |
| **AbuseIPDB** | IP reputation checking |
| **Shodan** | Port/service information |
| **AlienVault OTX** | Threat feeds |
| **GreyNoise** | Classification |

### 🤖 AI-Powered Analysis

- **OpenAI GPT** or **Google Gemini** powered threat analysis
- Automated risk scoring (0-100)
- Severity classification (LOW/MEDIUM/HIGH/CRITICAL)
- Turkish and English summaries
- Actionable recommendations

### 📊 Multi-Format Reporting

- Colorful terminal output
- JSON export
- Markdown reports
- HTML dashboard (coming soon)

### ⚡ Performance Features

- Asynchronous API calls
- Batch processing support
- Resilient architecture (provider fail-safe)
- Parallel IOC analysis

### 🔎 Supported IOC Types

- IPv4 & IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses

---

## 🚀 Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager
- API keys (see below)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/cyb3rkan/ioc-enricher-agent.git
cd ioc-enricher-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env file and add your API keys
```

---

## 🔑 API Keys

This tool uses API keys from the following services:

| Service | Required | Free Tier | Registration Link |
|---------|----------|-----------|-------------------|
| VirusTotal | ⭐ Required | ✅ 500 req/day | [Get Key](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ⭐ Required | ✅ 1000 req/day | [Get Key](https://www.abuseipdb.com/register) |
| Shodan | 📌 Recommended | ✅ Limited | [Get Key](https://account.shodan.io/register) |
| AlienVault OTX | 📌 Recommended | ✅ Free | [Get Key](https://otx.alienvault.com/api) |
| OpenAI | ⭐ Required* | ❌ Paid | [Get Key](https://platform.openai.com/signup) |
| Google Gemini | ⭐ Required* | ✅ Free | [Get Key](https://aistudio.google.com/app/apikey) |

*Choose either OpenAI or Gemini

### Configuration

Add your API keys to `.env` file:

```bash
# Threat Intelligence Providers
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here

# AI Provider (choose one)
AI_PROVIDER=openai  # or gemini
OPENAI_API_KEY=your_key_here  # if using OpenAI
GEMINI_API_KEY=your_key_here  # if using Gemini
```

---

## 💻 Usage

### CLI Usage

```bash
# Check provider status
python main.py --status

# Analyze a single IP
python main.py --ip 8.8.8.8

# Analyze a domain
python main.py --domain malicious-site.com

# Analyze a hash
python main.py --hash 44d88612fea8a8f36de82e1278abb02f

# Auto-detect IOC type
python main.py --ioc 1.1.1.1

# Batch analysis from file
python main.py --file example_iocs.txt

# Save as JSON
python main.py --ip 8.8.8.8 --format json --save

# Generate Markdown report
python main.py --ip 8.8.8.8 --format markdown --save
```

### Python API

```python
from src.enricher import IOCEnricher

# Initialize enricher
enricher = IOCEnricher()

# Analyze IP
result = enricher.analyze_ip("185.220.101.1")
print(result.risk_score)       # Risk score 0-100
print(result.summary)          # AI-generated summary
print(result.recommendations)  # Action recommendations

# Batch processing
iocs = ["8.8.8.8", "1.1.1.1", "malicious.com"]
results = enricher.analyze_batch(iocs)
```

---

## 📊 Sample Output

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
║  This IP address is a known Tor exit node and has been          ║
║  associated with malicious activity across multiple threat      ║
║  intelligence sources. High risk level requires immediate       ║
║  action.                                                        ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚡ RECOMMENDATIONS                                              ║
║  • Block this IP at firewall level                              ║
║  • Review logs for any connections                              ║
║  • Create alert rule in EDR/SIEM                                ║
║  • Initiate incident response procedure                         ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 📁 Project Structure

```
ioc-enricher-agent/
├── src/
│   ├── __init__.py
│   ├── enricher.py        # Main enrichment engine
│   ├── analyzer.py        # AI analysis module
│   ├── reporter.py        # Report generator
│   ├── config.py          # Configuration management
│   ├── validators.py      # IOC validation
│   └── providers/         # API integrations
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

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Quick Start Guide](docs/Quick_Start.md) | Get up and running in 5 minutes |
| [Testing Guide](docs/ReadMe_Test.md) | Comprehensive testing documentation |
| [Network Troubleshooting](docs/Network_Problems.md) | Fix connection issues |
| [Main Documentation](docs/ReadMe_Main.md) | Detailed feature documentation |

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python test_all.py

# Run unit tests only
pytest tests/test_enricher.py

# Run with coverage report
pytest --cov=src tests/
```

Expected results:

| Metric | Value |
|--------|-------|
| Total Tests | 42 |
| Passed | 40+ ✅ |
| Pass Rate | 95%+ |

---

## 🛡️ Security

| Feature | Implementation |
|---------|----------------|
| API Key Storage | Secure `.env` file (git-ignored) |
| Data Persistence | None (privacy-first) |
| Timeout Protection | ✅ Enabled |
| Rate Limiting | ✅ Supported |
| Error Handling | ✅ Comprehensive fallback mechanisms |
| Data Logging | ❌ Disabled for privacy |

---

## 🎯 Project Roadmap

| Feature | Status |
|---------|--------|
| Basic IOC parsing (IP, Domain, Hash) | ✅ Complete |
| VirusTotal integration | ✅ Complete |
| AbuseIPDB integration | ✅ Complete |
| Shodan integration | ✅ Complete |
| AlienVault OTX integration | ✅ Complete |
| AI-powered analysis (OpenAI & Gemini) | ✅ Complete |
| Batch processing | ✅ Complete |
| Multi-format reporting | ✅ Complete |
| Web interface (Streamlit) | 🔜 Planned |
| REST API endpoint | 🔜 Planned |
| Docker container | 🔜 Planned |
| CI/CD pipeline | 🔜 Planned |
| GreyNoise integration | 🔜 Planned |
| Dashboard visualizations | 🔜 Planned |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you would like to change.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/ioc-enricher-agent.git

# Create feature branch
git checkout -b feature/amazing-feature

# Commit your changes
git commit -m 'feat: add amazing feature'

# Push to branch
git push origin feature/amazing-feature

# Open Pull Request
```

### Contribution Guidelines

| Requirement | Description |
|-------------|-------------|
| Code Style | Follow PEP 8 standards |
| Test Coverage | Maintain 90%+ coverage |
| Documentation | Update relevant docs |
| Commit Messages | Use conventional commits |

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is **for educational and authorized security testing purposes only**. Unauthorized use on systems you don't own or have permission to test is illegal. Users are responsible for complying with all applicable laws.

**This tool:**
- Is designed for legitimate security research only
- Is not designed for malicious use
- Use is at user's own responsibility

---

## 🙏 Acknowledgments

| Provider | Purpose |
|----------|---------|
| VirusTotal | Comprehensive malware detection |
| AbuseIPDB | IP reputation data |
| Shodan | Infrastructure intelligence |
| AlienVault OTX | Threat pulse data |
| OpenAI & Google | AI analysis capabilities |

---

## 📧 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/erkansahin23/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cyb3rkan)

For questions, issues, or suggestions, please open an issue on GitHub.

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

*Making threat intelligence accessible to everyone*

</div>
