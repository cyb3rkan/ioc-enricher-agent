# 🔍 IOC Enricher Agent

**AI-Powered Threat Intelligence Aggregation & Analysis Tool**

A professional cybersecurity tool that aggregates data from multiple threat intelligence providers and uses AI to perform comprehensive Indicator of Compromise (IOC) analysis.

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-production-brightgreen)

---

## 🌟 Features

### 🎯 Core Capabilities
- **Multi-Provider Integration**: Aggregates data from 4+ threat intelligence sources
  - VirusTotal
  - AbuseIPDB
  - Shodan
  - AlienVault OTX
  
- **AI-Powered Analysis**: Intelligent risk assessment using OpenAI GPT or Google Gemini
  - Automated risk scoring (0-100)
  - Severity classification (LOW/MEDIUM/HIGH/CRITICAL)
  - Turkish and English summaries
  - Actionable recommendations
  
- **Multi-Format Reporting**
  - Colorful terminal output
  - JSON export
  - Markdown reports
  
- **Batch Processing**: Analyze multiple IOCs in parallel
- **Resilient Architecture**: Graceful degradation when providers fail

### 🔎 Supported IOC Types
- IPv4 & IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses

---

## 📊 Quick Stats

- **3,000+ Lines of Code**
- **15 Python Modules**
- **42 Test Cases**
- **7 API Integrations**
- **95%+ Test Pass Rate**

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ioc-enricher-agent.git
cd ioc-enricher-agent

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Add your API keys to `.env`:
```bash
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here  # or use Gemini
```

3. Choose your AI provider:
```bash
AI_PROVIDER=openai  # or gemini
```

### Usage

```bash
# Check provider status
python main.py --status

# Analyze single IOC
python main.py --ip 8.8.8.8
python main.py --domain google.com
python main.py --hash 44d88612fea8a8f36de82e1278abb02f

# Auto-detect IOC type
python main.py --ioc 1.1.1.1

# Batch processing
python main.py --file example_iocs.txt

# Save reports
python main.py --ip 8.8.8.8 --format json --save
python main.py --ip 8.8.8.8 --format markdown --save
```

---

## 📖 Documentation

- [**Quick Start Guide**](Quick_Start.md) - Get up and running in 5 minutes
- [**Testing Guide**](ReadMe_Test.md) - Comprehensive testing documentation
- [**Network Troubleshooting**](Network_Problems.md) - Fix common connection issues
- [**Main Documentation**](ReadMe_Main.md) - Detailed feature documentation

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
python test_all.py
```

Expected output:
```
Total Tests: 42
Passed: 40+ ✅
Pass Rate: 95%+
```

---

## 📊 Example Output

```
🔍 IOC ENRICHMENT REPORT

Target: 185.220.101.1
Type: IPV4
🎯 RISK SCORE: 55/100 🔴 HIGH

📊 THREAT INTELLIGENCE SOURCES
✓ VirusTotal
  └─ Detection: 14 malicious / 93 engines

✓ AbuseIPDB
  └─ Confidence Score: 100%, Total Reports: 178

🤖 AI ANALYSIS
This IP is associated with malicious activity. Multiple threat 
intelligence sources flag it as high-risk. Immediate action recommended.

⚡ RECOMMENDATIONS
  • Block this IP at firewall level
  • Review logs for any connections
  • Alert security team

Tags: tor-exit-node, malicious, high-risk
```

---

## 🏗️ Architecture

```
ioc-enricher-agent/
├── src/
│   ├── analyzer.py      # AI analysis engine
│   ├── enricher.py      # Main orchestrator
│   ├── reporter.py      # Multi-format reporting
│   ├── validators.py    # IOC validation
│   ├── config.py        # Configuration management
│   └── providers/       # Threat intelligence integrations
│       ├── virustotal.py
│       ├── abuseipdb.py
│       ├── shodan.py
│       └── otx.py
├── tests/               # Unit tests
├── main.py             # CLI interface
└── test_all.py         # Test suite
```

---

## 🔑 API Keys

Get your free API keys:

- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [AbuseIPDB](https://www.abuseipdb.com/register)
- [Shodan](https://account.shodan.io/register)
- [AlienVault OTX](https://otx.alienvault.com/api)
- [OpenAI](https://platform.openai.com/signup)
- [Google Gemini](https://aistudio.google.com/app/apikey)

---

## 🛡️ Security

- API keys stored in `.env` (git-ignored)
- No data persistence (privacy-first)
- Timeout protection
- Rate limiting support
- Error handling and fallback mechanisms

---

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- VirusTotal for comprehensive malware detection
- AbuseIPDB for IP reputation data
- Shodan for infrastructure intelligence
- AlienVault OTX for threat pulse data
- OpenAI & Google for AI analysis capabilities

---

## 📧 Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

## ⭐ Star History

If you find this project useful, please consider giving it a star!

---

**Built with ❤️ for the cybersecurity community**
