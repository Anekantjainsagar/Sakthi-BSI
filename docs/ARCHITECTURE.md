# BSI Architecture Documentation

## Overview

Business Security Intelligence (BSI) is a modular, multi-phase domain security analysis platform. The architecture is designed for:
- **Modularity** - Each phase is independent and can be extended
- **Scalability** - Parallel execution of phases
- **Maintainability** - Clear separation of concerns
- **Extensibility** - Easy to add new phases or services

## Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│                    Streamlit UI (app.py)                │
│              User Interface & Orchestration              │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                  Core Orchestration Layer                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ core/orchestrator.py - Analysis Orchestration   │   │
│  │ - Parallel phase execution                      │   │
│  │ - Resume capability                             │   │
│  │ - Progress tracking                             │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                    Analysis Phases Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Phase 1    │  │   Phase 2    │  │   Phase 3    │  │
│  │  Business    │  │Infrastructure│  │ Application  │  │
│  │  Intelligence│  │  Discovery   │  │  Landscape   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐                     │
│  │   Phase 4    │  │   Phase 5    │                     │
│  │  Correlation │  │     Risk     │                     │
│  │   & CVE      │  │ Assessment   │                     │
│  └──────────────┘  └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                  Data & Services Layer                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Database   │  │   Config     │  │   Utils      │  │
│  │   (SQLite)   │  │  Management  │  │  (Parsers,   │  │
│  │              │  │              │  │   Helpers)   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│              External APIs & Data Sources                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Business   │  │Infrastructure│  │ Threat Intel │  │
│  │   APIs       │  │   APIs       │  │   APIs       │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Module Descriptions

### 1. Configuration Layer (`config/`)

**Purpose:** Centralized configuration management

#### `config/gemini_config.py`
- Gemini AI API initialization
- API key rotation and management
- Model configuration
- Error handling for API calls

#### `config/api_config.py`
- External API endpoints and keys
- API rate limits
- Timeout configurations
- Retry policies

### 2. Core Layer (`core/`)

**Purpose:** Core business logic and data management

#### `core/database.py`
- SQLite database abstraction
- Analysis history tracking
- Phase result storage
- API response caching
- Thread-safe operations

**Key Classes:**
- `DatabaseManager` - Main database interface
- `AnalysisRecord` - Analysis metadata
- `PhaseResult` - Phase execution results
- `CacheEntry` - API response cache

#### `core/orchestrator.py`
- Analysis orchestration
- Phase execution management
- Resume capability
- Progress tracking
- Error handling

**Key Classes:**
- `BSIOrchestratorWithDB` - Main orchestrator
- `DatabaseIntegrationHelper` - Database helper

### 3. Analysis Phases (`phases/`)

**Purpose:** Domain analysis in 5 sequential phases

#### `phases/phase1_business.py`
**Input:** Domain name  
**Output:** Business intelligence data

**Functionality:**
- Company profile research
- Financial intelligence
- Leadership information
- Products and services
- Customer base analysis
- Regulatory compliance
- Threat intelligence

**Key Classes:**
- `CompanyIntelligenceAnalyzer` - Main analyzer

#### `phases/phase2_infrastructure.py`
**Input:** Domain name  
**Output:** Infrastructure topology

**Functionality:**
- Subdomain enumeration
- IP resolution
- Port scanning
- SSL/TLS analysis
- DNS records
- Mail server security
- IP reputation
- Co-hosted domains

**Key Classes:**
- `BSIInfrastructureDiscovery` - Main discovery engine

#### `phases/phase3_application.py`
**Input:** Domain name  
**Output:** Application stack inventory

**Functionality:**
- Web server detection
- CMS identification
- JavaScript library detection
- Third-party software
- API discovery
- Code repository exposure
- Outdated software
- Security headers

**Key Classes:**
- `CompleteBSIScanner` - Main scanner

#### `phases/phase4_correlation.py`
**Input:** Phases 1-3 data  
**Output:** Correlated threats and vulnerabilities

**Functionality:**
- CVE mapping
- Exploit availability
- APT correlation
- Attack vector analysis
- Security misconfiguration
- Data leak detection
- Threat aggregation

**Key Classes:**
- `AIPhase4Scanner` - Correlation engine

#### `phases/phase5_risk.py`
**Input:** Phase 4 correlation data  
**Output:** Risk assessment report

**Functionality:**
- Business risk evaluation
- Infrastructure risk scoring
- Application vulnerability density
- Business impact correlation
- Risk matrix generation
- Remediation recommendations

**Key Classes:**
- `RiskAssessmentEngine` - Risk assessment

### 4. UI Layer (`ui/`)

**Purpose:** User interface components

#### `ui/database_ui.py`
- Streamlit UI components
- Analysis history display
- Database management interface
- Result visualization

### 5. Utilities Layer (`utils/`)

**Purpose:** Helper functions and utilities

#### `utils/parsers.py`
- SpiderFoot CSV parsing
- Data extraction and normalization
- Subdomain extraction
- Type mapping

#### `utils/helpers.py`
- API limit checking
- Rate limiting
- Utility functions
- Common helpers

### 6. Services Layer (`services/`)

**Purpose:** Extensible service layer (for future expansion)

Currently a placeholder for:
- API client services
- Cache services
- Threat intelligence services
- Report generation services

### 7. Models Layer (`models/`)

**Purpose:** Data models (for future expansion)

Currently a placeholder for:
- Analysis models
- Result models
- Configuration models

## Data Flow

### Single Domain Analysis Flow

```
User Input (Domain)
        ↓
    app.py
        ↓
    BSIOrchestrator.analyze_domain_parallel()
        ↓
    ┌───────────────────────────────────────┐
    │  Parallel Execution (Phases 1-3)      │
    │  ├─ Phase 1: Business Intelligence   │
    │  ├─ Phase 2: Infrastructure          │
    │  └─ Phase 3: Application Landscape   │
    └───────────────────────────────────────┘
        ↓
    Wait for completion
        ↓
    Phase 4: Correlation & CVE Analysis
        ↓
    Phase 5: Risk Assessment
        ↓
    Generate Report
        ↓
    Save to Database
        ↓
    Display Results
```

### Resume Analysis Flow

```
User Input (Domain)
        ↓
    Check Database
        ↓
    Analysis Found?
    ├─ Yes → Resume from last phase
    └─ No  → Start new analysis
        ↓
    Continue from checkpoint
        ↓
    Complete remaining phases
        ↓
    Update database
        ↓
    Display results
```

## Database Schema

### Tables

#### `analysis_history`
```sql
CREATE TABLE analysis_history (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE,
    status TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    completion_percentage INTEGER,
    notes TEXT
);
```

#### `phase_results`
```sql
CREATE TABLE phase_results (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER,
    phase_number INTEGER,
    phase_name TEXT,
    status TEXT,
    result_data JSON,
    duration_seconds REAL,
    created_at TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
);
```

#### `api_cache`
```sql
CREATE TABLE api_cache (
    id INTEGER PRIMARY KEY,
    cache_key TEXT UNIQUE,
    api_name TEXT,
    domain TEXT,
    response_data JSON,
    created_at TIMESTAMP,
    expires_at TIMESTAMP
);
```

#### `analysis_summary`
```sql
CREATE TABLE analysis_summary (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER,
    summary_data JSON,
    created_at TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
);
```

## Import Convention

All imports follow a consistent pattern from project root:

```python
# Configuration
from config.gemini_config import call_gemini, GEMINI_MODEL, GEMINI_API_KEYS
from config.api_config import BUSINESS_DOMAIN_APIS, INFRA_DISCOVERY_APIS, APPLICATION_LANDSCAPE_APIS

# Core
from core.database import get_db_manager, DatabaseManager
from core.orchestrator import BSIOrchestratorWithDB, DatabaseIntegrationHelper

# Phases
from phases.phase1_business import CompanyIntelligenceAnalyzer
from phases.phase2_infrastructure import BSIInfrastructureDiscovery
from phases.phase3_application import CompleteBSIScanner
from phases.phase4_correlation import AIPhase4Scanner
from phases.phase5_risk import RiskAssessmentEngine

# UI
from ui.database_ui import display_analysis_history_sidebar

# Utils
from utils.parsers import parse_spiderfoot_csv, get_section_counts
from utils.helpers import check_api_limits
```

## Execution Flow

### Parallel Execution (Phases 1-3)

```python
with ThreadPoolExecutor(max_workers=3) as executor:
    future_phase1 = executor.submit(run_business_analysis, domain)
    future_phase2 = executor.submit(run_infrastructure_analysis, domain)
    future_phase3 = executor.submit(run_application_analysis, domain)
    
    # Wait for all to complete
    for future in as_completed([future_phase1, future_phase2, future_phase3]):
        result = future.result()
```

### Sequential Execution (Phases 4-5)

```python
# Phase 4 requires Phases 1-3 data
phase4_result = run_correlation_analysis(phase1, phase2, phase3)

# Phase 5 requires Phase 4 data
phase5_result = run_risk_assessment(phase4_result)
```

## Performance Characteristics

### Current Performance
- **Total Time:** 20-30 minutes per domain
- **Phase 1:** 5-8 minutes
- **Phase 2:** 3-5 minutes (port scanning bottleneck)
- **Phase 3:** 2-4 minutes
- **Phase 4:** 3-5 minutes (Gemini AI processing)
- **Phase 5:** 2-3 minutes

### Bottlenecks
1. Sequential API calls in Phase 1 (25-40% of time)
2. Port scanning in Phase 2 (15-25% of time)
3. Gemini AI processing (15-25% of time)
4. Web scraping in Phase 3 (10-20% of time)
5. DNS/WHOIS lookups (5-10% of time)

### Optimization Opportunities
- Parallel API calls within phases
- Request caching and memoization
- Async/await for I/O operations
- Connection pooling
- Batch processing

## Error Handling

### Phase-Level Error Handling
```python
try:
    result = phase_function()
except Exception as e:
    status = 'failed'
    error_message = str(e)
    # Continue with other phases
```

### Database Error Handling
```python
try:
    db.save_phase_result(...)
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    # Retry or fallback
```

### API Error Handling
```python
try:
    response = api_call()
except APIError as e:
    if e.status_code == 429:  # Rate limit
        time.sleep(backoff_time)
        retry()
    elif e.status_code == 503:  # Service unavailable
        use_fallback_api()
```

## Extensibility

### Adding a New Phase

1. Create `phases/phase6_newphase.py`
2. Implement phase class with required methods
3. Update `app.py` to include new phase
4. Update orchestrator to handle new phase
5. Add tests in `tests/`

### Adding a New Service

1. Create `services/new_service.py`
2. Implement service class
3. Register in configuration
4. Use in appropriate phase

### Adding a New API

1. Add API configuration to `config/api_config.py`
2. Create API client in `services/` or phase
3. Add error handling and retry logic
4. Add caching if applicable

## Testing Strategy

### Unit Tests
- Test individual phase functions
- Test database operations
- Test utility functions

### Integration Tests
- Test phase interactions
- Test database integration
- Test API integrations

### End-to-End Tests
- Test full analysis workflow
- Test resume capability
- Test error recovery

## Deployment Considerations

### Requirements
- Python 3.8+
- SQLite3
- External API keys
- Network access

### Configuration
- Set environment variables in `.env`
- Configure API keys
- Set database path
- Configure logging

### Monitoring
- Log all phase executions
- Track API usage
- Monitor database size
- Alert on failures

## Future Enhancements

1. **Distributed Execution** - Run phases on multiple machines
2. **Advanced Caching** - Redis/Memcached for distributed cache
3. **Machine Learning** - Threat prediction and anomaly detection
4. **SIEM Integration** - Send results to security information systems
5. **Custom Reports** - Configurable report generation
6. **API Endpoint** - RESTful API for programmatic access
7. **Web Dashboard** - Non-Streamlit web interface
8. **Batch Processing** - Analyze multiple domains in parallel

---

**Last Updated:** May 2026  
**Architecture Version:** 2.0 (Modular)
