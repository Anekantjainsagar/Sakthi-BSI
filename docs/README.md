# Business Security Intelligence (BSI) - Modular Architecture

A comprehensive domain security analysis platform that performs multi-phase reconnaissance and threat assessment.

## 🏗️ Project Structure

```
Sakthi-BSI/
├── config/                 # Configuration management
│   ├── __init__.py
│   ├── gemini_config.py   # Gemini AI API configuration
│   └── api_config.py      # External API keys and endpoints
│
├── core/                   # Core business logic
│   ├── __init__.py
│   ├── database.py        # SQLite database layer with analysis history
│   └── orchestrator.py    # Analysis orchestration and resume capability
│
├── phases/                 # Analysis phases (1-5)
│   ├── __init__.py
│   ├── phase1_business.py         # Business domain intelligence
│   ├── phase2_infrastructure.py   # Infrastructure discovery
│   ├── phase3_application.py      # Application landscape assessment
│   ├── phase4_correlation.py      # Threat correlation & CVE analysis
│   └── phase5_risk.py             # Risk assessment & categorization
│
├── ui/                     # User interface components
│   ├── __init__.py
│   └── database_ui.py     # Streamlit UI for database features
│
├── utils/                  # Utility functions
│   ├── __init__.py
│   ├── helpers.py         # API limit checking and helpers
│   └── parsers.py         # SpiderFoot CSV parser
│
├── services/               # Service layer (extensible)
│   └── __init__.py
│
├── models/                 # Data models (extensible)
│   └── __init__.py
│
├── tests/                  # Test suite
│   ├── __init__.py
│   └── test_database.py   # Database integration tests
│
├── docs/                   # Documentation
│   ├── README.md          # Project overview
│   ├── ARCHITECTURE.md    # System architecture
│   ├── QUICKSTART.md      # Quick start guide
│   ├── PROJECT_STATUS.md  # Project status
│   ├── CLEANUP_SUMMARY.md # Cleanup work
│   ├── REFACTORING_PROGRESS.md # Refactoring history
│   ├── BOTTLENECK_SUMMARY.txt  # Performance analysis
│   └── DOCUMENTATION_INDEX.md  # Documentation index
│
├── logs/                   # Application logs
├── reports/                # Generated reports
│
├── app.py                  # Main Streamlit application
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (API keys)
├── .gitignore             # Git ignore rules
└── INDEX.md               # Quick reference to docs/
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip or conda

### Installation

1. **Clone and setup:**
```bash
cd Sakthi-BSI
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure API keys:**
```bash
cp .env.example .env
# Edit .env with your API keys:
# - Gemini AI API key
# - Hunter.io API key
# - Host.io API key
# - AbstractAPI key
# - And other required APIs
```

3. **Run the application:**
```bash
streamlit run app.py
```

## 📊 Analysis Phases

### Phase 1: Business Domain Intelligence
- Company profile and background research
- Financial intelligence (revenue, funding, market cap)
- Leadership and organizational structure
- Products, services, and customer base
- Regulatory compliance requirements
- Threat intelligence (APT groups targeting industry)

**Input:** Domain name  
**Output:** Business context and risk profile

### Phase 2: Infrastructure Discovery
- Subdomain enumeration
- IP address resolution and geolocation
- Open port scanning
- SSL/TLS certificate analysis
- DNS records (A, MX, NS, CAA, DNSSEC)
- Mail server security (SPF, DMARC, DKIM)
- IP reputation and blacklist checks
- Co-hosted domains and infrastructure mapping

**Input:** Domain name  
**Output:** Infrastructure topology and security posture

### Phase 3: Application Landscape Assessment
- Web server technology detection
- CMS identification and version detection
- JavaScript library and framework detection
- Third-party software inventory
- API endpoint discovery
- Code repository exposure
- Outdated software detection
- Security header analysis
- Database detection

**Input:** Domain name  
**Output:** Application stack and technology inventory

### Phase 4: Threat Correlation & CVE Analysis
- CVE mapping to detected technologies
- Exploit availability checking
- APT threat actor correlation
- Attack vector analysis
- Security misconfiguration assessment
- Data leak detection (PasteBin, dark web)
- Threat intelligence aggregation

**Input:** Phases 1-3 data  
**Output:** Correlated threats and vulnerabilities

### Phase 5: Risk Assessment & Categorization
- Business risk evaluation
- Infrastructure risk scoring
- Application vulnerability density
- Business impact correlation
- Risk matrix generation
- Remediation recommendations

**Input:** Phase 4 correlation data  
**Output:** Executive risk report

## 🗄️ Database Features

### Analysis History
- Track all domain analyses
- Resume interrupted analyses
- Search historical results
- Automatic result caching

### API Response Caching
- Cache external API responses
- Configurable TTL (time-to-live)
- Reduce API costs and improve speed
- Automatic cache invalidation

### Usage Example
```python
from core.database import get_db_manager
from core.orchestrator import BSIOrchestratorWithDB

# Initialize database
db = get_db_manager("bsi.db")

# Create new analysis
analysis_id = db.create_analysis("example.com")

# Save phase results
db.save_phase_result(analysis_id, 1, "Business Domain", phase_data, duration_seconds=45)

# Resume interrupted analysis
orchestrator = BSIOrchestratorWithDB("bsi.db")
orchestrator.resume_analysis("example.com")
```

## ⚙️ Configuration

### Environment Variables (.env)
```
# Gemini AI
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-1.5-pro

# Business Domain APIs
HUNTER_IO_API_KEY=your_key_here
HOST_IO_API_KEY=your_key_here
ABSTRACTAPI_KEY=your_key_here

# Infrastructure APIs
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here

# Application APIs
WHATCMS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Threat Intelligence
ABUSEIPDB_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
```

## 🧪 Testing

Run the test suite:
```bash
python -m pytest tests/
```

Or run specific tests:
```bash
python tests/test_database.py
```

## 📈 Performance Optimization

### Bottleneck Analysis
See `docs/BOTTLENECK_SUMMARY.txt` for identified performance bottlenecks and optimization strategies.

### Key Optimizations
- Parallel phase execution (Phases 1-3 run concurrently)
- API response caching with configurable TTL
- Database indexing for fast lookups
- Async/await for I/O operations
- Request timeouts to prevent hanging

## 🔒 Security Considerations

- API keys stored in `.env` (never commit to git)
- Database encryption for sensitive data
- HTTPS for all external API calls
- Input validation on all user inputs
- Rate limiting on API calls
- Secure credential storage

## 📝 Import Convention

All imports follow a consistent pattern from project root:

```python
# Config
from config.gemini_config import call_gemini, GEMINI_MODEL, GEMINI_API_KEYS
from config.api_config import BUSINESS_DOMAIN_APIS, INFRA_DISCOVERY_APIS

# Core
from core.database import get_db_manager
from core.orchestrator import BSIOrchestratorWithDB

# Phases
from phases.phase1_business import CompanyIntelligenceAnalyzer
from phases.phase2_infrastructure import BSIInfrastructureDiscovery
from phases.phase3_application import CompleteBSIScanner
from phases.phase4_correlation import AIPhase4Scanner
from phases.phase5_risk import RiskAssessmentEngine

# Utils
from utils.parsers import parse_spiderfoot_csv
from utils.helpers import check_api_limits

# UI
from ui.database_ui import display_analysis_history_sidebar
```

## 🤝 Contributing

1. Follow the modular structure
2. Add new features to appropriate phase or service
3. Update imports to use new modular paths
4. Add tests for new functionality
5. Update documentation

## 📄 License

[Add your license here]

## 📞 Support

For issues or questions, please open an issue on the project repository.

## 🎯 Roadmap

- [ ] Parallel API calls within phases
- [ ] Advanced caching strategies
- [ ] Machine learning for threat prediction
- [ ] Integration with SIEM systems
- [ ] Custom report generation
- [ ] API endpoint for programmatic access
- [ ] Web dashboard (non-Streamlit)
- [ ] Multi-domain batch analysis

## 📊 Project Statistics

- **5 Analysis Phases** - Comprehensive reconnaissance
- **50+ External APIs** - Integrated threat intelligence
- **SQLite Database** - Local analysis history
- **Modular Architecture** - Easy to extend and maintain
- **Parallel Execution** - Fast analysis (20-30 min → target: 5-10 min)

---

**Last Updated:** May 2026  
**Version:** 2.0 (Modular Architecture)

**📖 For detailed documentation, see the [Documentation Index](DOCUMENTATION_INDEX.md)**
