# Response Time Optimization - Design Specification

**Status**: Design Phase  
**Target**: Tier 1 + Tier 2 optimizations (65% reduction)

---

## 🏗️ Architecture Changes

### Current Architecture
```
ThreadPoolExecutor (3 workers)
├── Phase 1: requests.Session() [BLOCKING]
├── Phase 2: asyncio + aiohttp [ASYNC]
└── Phase 3: requests.Session() [BLOCKING]
    ↓ (Sequential)
Phase 4: requests.Session() + Gemini [BLOCKING]
    ↓ (Sequential)
Phase 5: Synchronous [BLOCKING]
```

### Target Architecture
```
asyncio Event Loop (Global)
├── Phase 1: aiohttp.ClientSession() [ASYNC] ✨
├── Phase 2: aiohttp.ClientSession() [ASYNC] (optimized)
├── Phase 3: aiohttp.ClientSession() [ASYNC] ✨
└── Phase 3.5: Dark Web [ASYNC] (parallel)
    ↓ (Wait for all)
Phase 4: aiohttp.ClientSession() + Gemini [ASYNC] ✨
    ↓ (Sequential - data dependent)
Phase 5: Synchronous [BLOCKING] (no I/O)

Global Connection Pool (Shared)
├── HTTP connections (reused)
├── DNS resolver (async)
└── Cache layer (Redis/SQLite)
```

---

## 🔧 Component Design

### 1. Global Connection Pool (`core/connection_pool.py`)

**Purpose**: Centralized connection management across all phases

**Design**:
```python
class ConnectionPool:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.connector: Optional[aiohttp.TCPConnector] = None
        self.cache: Optional[CacheManager] = None
    
    async def initialize(self):
        """Initialize global session and connector"""
        self.connector = aiohttp.TCPConnector(
            limit=100,              # Max connections
            limit_per_host=10,      # Max per host
            ttl_dns_cache=300,      # DNS cache 5 minutes
            ssl=False               # Allow self-signed certs
        )
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30, connect=10)
        )
        self.cache = CacheManager()
    
    async def close(self):
        """Close session and cleanup"""
        if self.session:
            await self.session.close()
    
    def get_session(self) -> aiohttp.ClientSession:
        """Get global session"""
        return self.session
    
    def get_cache(self) -> CacheManager:
        """Get cache manager"""
        return self.cache

# Global instance
_pool: Optional[ConnectionPool] = None

async def get_connection_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool()
        await _pool.initialize()
    return _pool
```

**Benefits**:
- Reuses TCP connections across phases
- Reduces connection overhead by 5-10%
- Centralized timeout management
- DNS caching

---

### 2. Cache Manager (`core/cache_manager.py`)

**Purpose**: Cache API responses to avoid redundant calls

**Design**:
```python
class CacheManager:
    def __init__(self, backend: str = "sqlite"):
        self.backend = backend  # "sqlite" or "redis"
        self.db = None
    
    async def get(self, key: str) -> Optional[Dict]:
        """Get cached value"""
        # Check TTL
        # Return value if valid
        pass
    
    async def set(self, key: str, value: Dict, ttl_hours: int = 24):
        """Cache value with TTL"""
        pass
    
    async def invalidate(self, pattern: str):
        """Invalidate cache by pattern"""
        pass

# Cache keys by phase
CACHE_KEYS = {
    "phase1_hunter": "phase1:hunter:{domain}",
    "phase1_hostio": "phase1:hostio:{domain}",
    "phase2_subdomains": "phase2:subdomains:{domain}",
    "phase2_ip_reputation": "phase2:ip_rep:{ip}",
    "phase3_threat_intel": "phase3:threat:{ip}",
}

# TTL by data type
CACHE_TTL = {
    "api_response": 24,      # 24 hours
    "subdomain_list": 24,    # 24 hours
    "ip_reputation": 24,     # 24 hours
    "threat_intel": 24,      # 24 hours
    "ssl_cert": 168,         # 7 days
}
```

**Benefits**:
- Eliminates redundant API calls
- 5-10% improvement on repeated domains
- Configurable TTL per data type
- Easy to invalidate

---

### 3. Phase 1 Async Refactor

**Current Flow** (Sequential):
```
Hunter.io (3-5s) → Host.io (3-5s) → AbstractAPI (2-3s) 
→ WHOIS (2-3s) → Scraping (5-10s) → Gemini (10-15s)
= 25-41s total
```

**Target Flow** (Parallel):
```
┌─ Hunter.io (3-5s)
├─ Host.io (3-5s)
├─ AbstractAPI (2-3s)
├─ WHOIS (2-3s)
└─ Scraping (5-10s)
= 5-10s total (parallel)
+ Gemini (10-15s) = 15-25s total
```

**Implementation**:
```python
# phases/phase1/analyzer.py
async def analyze_company_async(self, company_name: str, domain: str):
    """Async version of analyze_company"""
    
    # Check cache first
    cache_key = f"phase1_analysis:{domain}"
    cached = await self.cache.get(cache_key)
    if cached:
        return cached
    
    # Run all API calls in parallel
    results = await asyncio.gather(
        self.api_queries.query_hunter_io_async(domain),
        self.api_queries.query_hostio_async(domain),
        self.api_queries.query_abstractapi_async(domain),
        self.data_extraction.get_whois_async(domain),
        self.data_extraction.scrape_website_async(domain),
        return_exceptions=True
    )
    
    hunter_data, hostio_data, abstract_data, whois_data, scraped_data = results
    
    # Combine results
    combined_data = {
        'hunter_io': hunter_data,
        'host_io': hostio_data,
        'abstractapi_company': abstract_data,
        'whois_data': whois_data,
        'scraped_data': scraped_data
    }
    
    # Call Gemini (can be parallel with Phase 2/3)
    ai_analysis = await self.ai_analysis.analyze_with_gemini_async(combined_data)
    combined_data['ai_analysis'] = ai_analysis
    
    # Cache result
    await self.cache.set(cache_key, combined_data, ttl_hours=24)
    
    return combined_data
```

**Files to Modify**:
- `phases/phase1/analyzer.py` - Add async methods
- `phases/phase1/api_queries.py` - Convert to async
- `phases/phase1/data_extraction.py` - Convert to async

---

### 4. Phase 2 Optimization

**Subdomain Discovery** (Parallel):
```python
# phases/phase2/subdomain_discovery.py
async def discover_subdomains_parallel(self, domain: str):
    """Parallel subdomain discovery from all sources"""
    
    results = await asyncio.gather(
        self._query_crtsh(domain),
        self._query_hackertarget(domain),
        self._query_fullhunt(domain),
        self._query_projectdiscovery(domain),
        return_exceptions=True
    )
    
    # Merge and deduplicate
    all_subdomains = set()
    for result in results:
        if isinstance(result, list):
            all_subdomains.update(result)
    
    return list(all_subdomains)
```

**IP Reputation** (Parallel per IP):
```python
# phases/phase2/ip_analysis.py
async def check_ip_reputation_parallel(self, ips: List[str]):
    """Parallel IP reputation checks"""
    
    tasks = []
    for ip in ips:
        task = asyncio.gather(
            self._check_ipapi(ip),
            self._check_ipinfo(ip),
            self._check_ipregistry(ip),
            self._check_neutrinoapi(ip),
            self._check_networksdb(ip),
            return_exceptions=True
        )
        tasks.append(task)
    
    # Process in batches of 20
    results = []
    for batch in self._batch(tasks, 20):
        batch_results = await asyncio.gather(*batch)
        results.extend(batch_results)
    
    return results
```

**Subdomain Verification** (Larger batches):
```python
# phases/phase2/discovery_full.py
async def verify_subdomains_optimized(self, subdomains: List[str]):
    """Verify subdomains with larger batches"""
    
    verified = []
    batch_size = 200  # Increased from 50
    sleep_time = 0.2  # Reduced from 1.0
    
    for batch in self._batch(subdomains, batch_size):
        tasks = [self._verify_subdomain(sub) for sub in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        verified.extend([r for r in batch_results if r])
        
        await asyncio.sleep(sleep_time)
    
    return verified
```

**Files to Modify**:
- `phases/phase2/subdomain_discovery.py` - Parallel sources
- `phases/phase2/ip_analysis.py` - Parallel APIs per IP
- `phases/phase2/discovery_full.py` - Larger batches

---

### 5. Phase 3 Async Refactor

**Threat Intelligence** (Parallel):
```python
# phases/phase3/security_analysis.py
async def check_threat_intel_parallel(self, ips: List[str]):
    """Parallel threat intelligence checks"""
    
    tasks = []
    for ip in ips:
        task = asyncio.gather(
            self._check_metadefender(ip),
            self._check_abuseipdb(ip),
            self._check_alienvault(ip),
            self._check_greynoise(ip),
            self._check_virustotal(ip),
            self._check_pulsedive(ip),
            return_exceptions=True
        )
        tasks.append(task)
    
    # Process in batches of 20
    results = []
    for batch in self._batch(tasks, 20):
        batch_results = await asyncio.gather(*batch)
        results.extend(batch_results)
    
    return results
```

**Files to Modify**:
- `phases/phase3/security_analysis.py` - Parallel APIs
- `phases/phase3/scanner.py` - Convert to async

---

### 6. Phase 4 Optimization

**Remove File I/O**:
```python
# core/orchestrator_bsi.py
async def run_correlation_analysis(self, domain: str) -> Dict[str, Any]:
    """Phase 4 without temp files"""
    
    # Get data from memory (not files)
    phase1_data = self.results.get('business_domain', {})
    phase2_data = self.results.get('infrastructure', {})
    phase3_data = self.results.get('application_landscape', {})
    dark_web_data = self.results.get('dark_web_intelligence', {})
    
    # Pass directly to scanner
    scanner = AIPhase4Scanner()
    result = await scanner.run_correlation_async(
        phase1_data=phase1_data,
        phase2_data=phase2_data,
        phase3_data=phase3_data,
        dark_web_data=dark_web_data
    )
    
    return result
```

**Parallel Gemini Calls**:
```python
# phases/phase4/scanner.py
async def run_correlation_async(self, phase1_data, phase2_data, phase3_data, dark_web_data):
    """Parallel Gemini calls for correlation"""
    
    # Prepare prompts
    cve_prompt = self._prepare_cve_prompt(phase2_data, phase3_data)
    apt_prompt = self._prepare_apt_prompt(phase1_data, phase2_data)
    attack_prompt = self._prepare_attack_prompt(phase3_data)
    
    # Run all Gemini calls in parallel
    results = await asyncio.gather(
        self._call_gemini_async(cve_prompt),
        self._call_gemini_async(apt_prompt),
        self._call_gemini_async(attack_prompt),
        return_exceptions=True
    )
    
    cve_analysis, apt_analysis, attack_analysis = results
    
    return {
        'cve_analysis': cve_analysis,
        'apt_analysis': apt_analysis,
        'attack_analysis': attack_analysis
    }
```

**Files to Modify**:
- `core/orchestrator_bsi.py` - Remove file I/O
- `phases/phase4/scanner.py` - Parallel Gemini calls

---

### 7. Orchestrator Refactor

**Current** (ThreadPoolExecutor):
```python
with ThreadPoolExecutor(max_workers=3) as executor:
    future_business = executor.submit(self.run_business_analysis, domain)
    future_infrastructure = executor.submit(self.run_infrastructure_wrapper, domain)
    future_application = executor.submit(self.run_application_analysis, domain)
    
    for future in as_completed(futures):
        # Wait for completion
```

**Target** (Pure asyncio):
```python
async def analyze_domain_parallel_async(self, domain: str):
    """Pure async orchestration"""
    
    # Phase 1-3 + Dark Web in parallel
    results = await asyncio.gather(
        self.run_business_analysis_async(domain),
        self.run_infrastructure_analysis_async(domain),
        self.run_application_analysis_async(domain),
        self.run_dark_web_analysis_async(domain),
        return_exceptions=True
    )
    
    # Phase 4 (sequential - data dependent)
    await self.run_correlation_analysis_async(domain)
    
    # Phase 5 (sequential - data dependent)
    await self.run_risk_assessment_async(domain)
```

**Files to Modify**:
- `core/orchestrator_bsi.py` - Pure async

---

## 📊 Performance Impact

### Phase 1 Optimization
- **Before**: 5-8m (sequential APIs)
- **After**: 1-2m (parallel APIs)
- **Savings**: 75% (4-6m)

### Phase 2 Optimization
- **Before**: 3-5m (sequential phases)
- **After**: 1-1.5m (parallel discovery, verification, IP reputation)
- **Savings**: 65% (1.5-3.5m)

### Phase 3 Optimization
- **Before**: 2-4m (sequential scans)
- **After**: 0.5-1m (parallel threat intel)
- **Savings**: 75% (1.5-3m)

### Phase 4 Optimization
- **Before**: 3-5m (file I/O + sequential Gemini)
- **After**: 1-1.5m (no file I/O + parallel Gemini)
- **Savings**: 65% (1.5-3.5m)

### Phase 5 (No change)
- **Before**: 2-3m
- **After**: 2-3m
- **Savings**: 0%

### Total
- **Before**: 20-30m
- **After**: 7-10m
- **Savings**: 65% (10-20m)

---

## 🔄 Data Flow

### Current (Sequential)
```
Phase 1 (5-8m)
    ↓
Phase 2 (3-5m)
    ↓
Phase 3 (2-4m)
    ↓
Phase 4 (3-5m)
    ↓
Phase 5 (2-3m)
= 20-30m total
```

### Target (Optimized)
```
Phase 1 (1-2m) ┐
Phase 2 (1-1.5m) ├─ Parallel (1-2m)
Phase 3 (0.5-1m) ┤
Dark Web (0.5s) ┘
    ↓
Phase 4 (1-1.5m)
    ↓
Phase 5 (2-3m)
= 7-10m total
```

---

## ✅ Quality Assurance

### Data Integrity
- ✅ Same APIs called (just parallel)
- ✅ Same data collected
- ✅ Same analysis performed
- ✅ Same results generated

### Error Handling
- ✅ All retry logic maintained
- ✅ All timeout logic maintained
- ✅ All error handling maintained
- ✅ All logging maintained

### Testing Strategy
- Unit tests for each async function
- Integration tests for phase orchestration
- Performance tests to verify timing improvements
- Data validation tests to ensure no quality loss

---

## 📋 Implementation Checklist

### Phase 1 Async
- [ ] Create `phases/phase1/api_queries_async.py`
- [ ] Update `phases/phase1/analyzer.py` with async methods
- [ ] Update `phases/phase1/data_extraction.py` with async methods
- [ ] Add cache integration
- [ ] Test and verify

### Phase 2 Optimization
- [ ] Update `phases/phase2/subdomain_discovery.py` for parallel sources
- [ ] Update `phases/phase2/ip_analysis.py` for parallel APIs
- [ ] Update `phases/phase2/discovery_full.py` for larger batches
- [ ] Add cache integration
- [ ] Test and verify

### Phase 3 Async
- [ ] Update `phases/phase3/security_analysis.py` for parallel APIs
- [ ] Update `phases/phase3/scanner.py` with async methods
- [ ] Add cache integration
- [ ] Test and verify

### Phase 4 Optimization
- [ ] Remove temp file I/O from `core/orchestrator_bsi.py`
- [ ] Update `phases/phase4/scanner.py` for parallel Gemini calls
- [ ] Update `config/gemini_config.py` for async support
- [ ] Test and verify

### Infrastructure
- [ ] Create `core/connection_pool.py`
- [ ] Create `core/cache_manager.py`
- [ ] Update `app.py` to initialize pool and cache
- [ ] Update `core/orchestrator_bsi.py` for pure async
- [ ] Test and verify

---

## 🚀 Next Steps

1. Review design specification
2. Approve implementation order
3. Create detailed task breakdown
4. Begin implementation with Phase 1 Async

