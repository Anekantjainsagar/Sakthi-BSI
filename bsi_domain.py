#!/usr/bin/env python3
"""
Business Domain Understanding Module for BSI - UPDATED VERSION
Focused on business intelligence with AI-driven compliance recommendations
"""

import time
import os
import requests
from typing import Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup
import re
import json
from dotenv import load_dotenv
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# Import centralized API config
try:
    from bsi_api_config import BUSINESS_DOMAIN_APIS
    API_CONFIG_AVAILABLE = True
    print("✅ API Config loaded successfully")
except ImportError:
    API_CONFIG_AVAILABLE = False
    print("⚠ bsi_api_config.py not found. Using fallback mode.")

# Try multiple whois libraries
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from gemini_config import call_gemini as _gemini_call, GEMINI_MODEL, GEMINI_API_KEYS

# GEMINI_AVAILABLE derived from gemini_config — no direct genai import needed
GEMINI_AVAILABLE = len(GEMINI_API_KEYS) > 0

# Fallback to Ollama
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class CompanyIntelligenceAnalyzer:
    def __init__(self):
        # Configure Gemini API
        self.use_gemini = False
        
        print("\n" + "="*60)
        print("🔧 Initializing AI Services...")
        print("="*60)
        
        if GEMINI_AVAILABLE and len(GEMINI_API_KEYS) > 0:
            self.use_gemini = True
            print(f"✅ Gemini AI initialized ({GEMINI_MODEL}, {len(GEMINI_API_KEYS)} keys)")
            print(f"   Status: ACTIVE")
        else:
            print("❌ Gemini not available (library missing or no keys in .env)")
            self.use_gemini = False
        
        print("="*60 + "\n")
    
    def extract_financial_data_from_html(self, soup: BeautifulSoup, domain: str) -> Dict[str, Any]:
        """
        Extract ONLY FINANCIAL DATA from HTML (no employees, no compliance)
        Focus: Revenue, Funding, Market Cap, Growth metrics
        """
        financial_data = {
            'revenue': None,
            'quarterly_revenue': None,
            'revenue_growth': None,
            'market_cap': None,
            'funding_raised': None,
            'profitability': None,
            'founded': None  # Keep founded for consolidation
        }
        
        # Method 1: JSON-LD structured data
        json_ld_scripts = soup.find_all('script', type='application/ld+json')
        
        for script in json_ld_scripts:
            try:
                data = json.loads(script.string)
                
                if isinstance(data, list):
                    for item in data:
                        self._extract_financial_from_jsonld(item, financial_data)
                else:
                    self._extract_financial_from_jsonld(data, financial_data)
            except:
                continue
        
        # Method 2: Meta tags for financial data
        for meta in soup.find_all('meta'):
            property_val = meta.get('property', '').lower()
            name_val = meta.get('name', '').lower()
            content = meta.get('content', '')
            
            if not content:
                continue
            
            # Look for revenue mentions
            if 'revenue' in property_val or 'revenue' in name_val:
                financial_data['revenue'] = content
        
        # Method 3: Text analysis for financial patterns
        page_text = soup.get_text()
        
        # Find revenue
        revenue_patterns = [
            r'\$[\d,]+\.?\d*\s*(?:million|billion|M|B)\s+(?:in\s+)?revenue',
            r'revenue\s+of\s+\$?[\d,]+\.?\d*\s*(?:million|billion)',
            r'reported\s+\$?[\d,]+\.?\d*\s*(?:million|billion)',
        ]
        
        for pattern in revenue_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match and not financial_data['revenue']:
                financial_data['revenue'] = match.group(0)
                break
        
        # Find founded date (for consolidation)
        founded_patterns = [
            r'(?:Founded|Established)[:\s]+(\d{4})',
            r'(?:Since|Est\.)\s+(\d{4})',
        ]
        
        for pattern in founded_patterns:
            match = re.search(pattern, page_text)
            if match and not financial_data['founded']:
                year = int(match.group(1))
                if 1800 <= year <= datetime.now().year:
                    financial_data['founded'] = str(year)
                    break
        
        return financial_data
    
    def _extract_financial_from_jsonld(self, data: dict, output: dict):
        """Helper: Extract financial data from JSON-LD"""
        if not isinstance(data, dict):
            return
        
        if data.get('@type') in ['Organization', 'Corporation', 'LocalBusiness']:
            # Revenue
            if 'revenue' in data and not output['revenue']:
                output['revenue'] = str(data['revenue'])
            
            # Founded
            if 'foundingDate' in data and not output['founded']:
                founding = data['foundingDate']
                year_match = re.search(r'(\d{4})', str(founding))
                if year_match:
                    output['founded'] = year_match.group(1)

    def search_google_for_financial_data(self, company_name: str, domain: str) -> Dict[str, Any]:
        """
        Search Google using Serper API for FINANCIAL DATA ONLY
        Removed: Employees, Compliance searches
        """
        print(f"🔍 Searching Google for financial data: {company_name}...")
        
        SERPER_API_KEY = os.environ.get('SERPER_API_KEY', 'YOUR_SERPER_API_KEY_HERE')
        
        if not SERPER_API_KEY or SERPER_API_KEY == 'YOUR_SERPER_API_KEY_HERE':
            print("   ⚠️ No Serper API key found.")
            return {
                'revenue': None,
                'quarterly_revenue': None,
                'revenue_growth': None,
                'ticker': None,
                'headquarters': None,
                'ceo': None,
                'founded': None,
                'founder': None,
                'market_cap': None,
                'funding_raised': None,
                'profitability': None
            }
        
        print(f"   ✅ Using Serper API key: {SERPER_API_KEY[:20]}...")
        
        search_data = {
            'revenue': None,
            'quarterly_revenue': None,
            'revenue_growth': None,
            'ticker': None,
            'headquarters': None,
            'ceo': None,
            'founded': None,
            'founder': None,
            'market_cap': None,
            'funding_raised': None,
            'profitability': None,
            'compliance_found': [],
            'ceo_raw_text': '',
            'founder_raw_text': ''
        }
        
        url = "https://google.serper.dev/search"
        headers = {
            'X-API-KEY': SERPER_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Financial-focused searches + compliance discovery
        # Include domain in key searches to avoid ambiguity (e.g. "Domo Chemicals" vs "Domo Inc.")
        searches = {
            'revenue': f'"{company_name}" {domain} annual revenue 2024',
            'quarterly': f'"{company_name}" quarterly revenue 2024 2025',
            'revenue_growth': f'"{company_name}" revenue growth year over year',
            'ticker': f"{company_name} stock ticker symbol NYSE NASDAQ",
            'headquarters': f'"{company_name}" headquarters location',
            'ceo': f'"{company_name}" CEO chief executive officer',
            'ceo_linkedin': f'site:linkedin.com "{company_name}" CEO OR "Chief Executive Officer"',
            'founder': f'"{company_name}" founder founded by',
            'market_cap': f'"{company_name}" market capitalization',
            'funding': f'"{company_name}" total funding raised',
            'profitability': f'"{company_name}" profitable earnings',
            'compliance_certs': f'"{company_name}" ISO 27001 OR SOC 2 OR PCI DSS OR HIPAA certified',
            'compliance_public': f'site:{domain} compliance OR certifications OR security standards'
        }
        
        for key, query in searches.items():
            try:
                print(f"   🔎 Searching: {query}")
                
                payload = json.dumps({"q": query, "num": 10})
                response = requests.post(url, headers=headers, data=payload, timeout=10)
                
                if response.status_code == 200:
                    results = response.json()
                    combined_text = ""
                    
                    # Get answer box
                    if 'answerBox' in results:
                        answer = results['answerBox']
                        if 'answer' in answer:
                            combined_text += answer['answer'] + " "
                        if 'snippet' in answer:
                            combined_text += answer['snippet'] + " "
                    
                    # Get knowledge graph
                    if 'knowledgeGraph' in results:
                        kg = results['knowledgeGraph']
                        if 'description' in kg:
                            combined_text += kg['description'] + " "
                        if 'attributes' in kg:
                            for attr_key, attr_value in kg['attributes'].items():
                                combined_text += f"{attr_key}: {attr_value} "
                    
                    # Get organic results
                    if 'organic' in results:
                        for result in results['organic'][:5]:
                            if 'snippet' in result:
                                combined_text += result['snippet'] + " "
                            if 'title' in result:
                                combined_text += result['title'] + " "
                    
                    print(f"   📄 Got {len(combined_text)} characters of text")
                    
                    # Extract based on search type
                    if key in ['revenue', 'quarterly']:
                        patterns = [
                            r'\$[\d,]+\.?\d*\s*(?:million|billion|M|B)',
                            r'[\d,]+\.?\d*\s+million\s+(?:in\s+)?(?:total\s+)?revenue',
                            r'revenue\s+of\s+\$?[\d,]+\.?\d*\s*(?:million|billion)',
                        ]
                        
                        for pattern in patterns:
                            match = re.search(pattern, combined_text, re.IGNORECASE)
                            if match:
                                found = match.group(0)
                                if '$' not in found:
                                    found = '$' + found
                                found = found.strip()
                                
                                if key == 'revenue':
                                    search_data['revenue'] = found
                                    print(f"   ✅ Found revenue: {found}")
                                else:
                                    # Only store quarterly if it differs from annual revenue
                                    # (private companies often don't publish quarterly separately)
                                    if found != search_data.get('revenue'):
                                        search_data['quarterly_revenue'] = found
                                        print(f"   ✅ Found quarterly: {found}")
                                    else:
                                        print(f"   ℹ️ Quarterly same as annual — skipping (private company)")
                                break
                    
                    elif key == 'revenue_growth':
                        patterns = [
                            r'(\d+\.?\d*)\s*%\s*growth',
                            r'grew\s+(\d+\.?\d*)\s*%',
                            r'increased\s+(\d+\.?\d*)\s*%',
                        ]
                        for pattern in patterns:
                            match = re.search(pattern, combined_text, re.IGNORECASE)
                            if match:
                                search_data['revenue_growth'] = match.group(1) + '%'
                                print(f"   ✅ Found growth: {search_data['revenue_growth']}")
                                break
                    
                    elif key == 'ticker':
                        # Only set ticker if a stock exchange is explicitly mentioned
                        is_publicly_traded = any(
                            word in combined_text.upper()
                            for word in ['NASDAQ:', 'NYSE:', 'NASDAQ (', 'NYSE (', 'PUBLICLY TRADED', 'PUBLIC COMPANY', 'STOCK EXCHANGE']
                        )
                        if is_publicly_traded:
                            patterns = [
                                r'NASDAQ[:\s\(]+([A-Z]{2,5})',
                                r'NYSE[:\s\(]+([A-Z]{2,5})',
                                r'ticker[:\s]+([A-Z]{2,5})',
                            ]
                            for pattern in patterns:
                                match = re.search(pattern, combined_text, re.IGNORECASE)
                                if match:
                                    candidate = match.group(1).upper()
                                    # Validate: domain root must appear in the same search
                                    # results — otherwise ticker belongs to a different company
                                    domain_root = domain.split('.')[0].lower()  # "domochemicals"
                                    if domain_root in combined_text.lower():
                                        search_data['ticker'] = candidate
                                        print(f"   ✅ Found ticker: {candidate}")
                                    else:
                                        print(f"   ⚠️ Ticker '{candidate}' rejected — belongs to a different company (domain not in results)")
                                        print(f"   ℹ️ Treating as private company")
                                    break
                        else:
                            print(f"   ℹ️ No stock exchange mentioned — treating as private company")
                    
                    elif key == 'headquarters':
                        patterns = [
                            r'headquartered in ((?:[A-Za-z\s]+,\s*)?[A-Za-z\s]{2,30}?)(?:\s*[,\.]|\s+(?:has|is|was|with|and|the|a\s))',
                            r'headquarters[:\s]+([A-Za-z,\s]{3,40}?)(?:\s*[,\.\|]|$)',
                            r'based in ([A-Za-z,\s]{3,30}?)(?:\s*[,\.\|]|\s+(?:has|is|was|with|and))',
                        ]
                        for pattern in patterns:
                            match = re.search(pattern, combined_text, re.IGNORECASE)
                            if match:
                                hq = match.group(1).strip().rstrip(',')
                                # Keep only if it looks like a real location (not a sentence fragment)
                                if len(hq) <= 40 and not any(w in hq.lower() for w in ['has ', 'is ', 'was ', 'with ', 'produces', 'chemicals']):
                                    search_data['headquarters'] = hq
                                    print(f"   ✅ Found HQ: {hq}")
                                    break
                    
                    elif key in ['ceo', 'ceo_linkedin']:
                        # Store raw text — let Gemini extract the name (much more reliable than regex)
                        search_data['ceo_raw_text'] += combined_text + " "
                    
                    elif key == 'founder':
                        # Store raw text — let Gemini extract the name
                        search_data['founder_raw_text'] += combined_text + " "
                    
                    elif key == 'market_cap':
                        patterns = [
                            r'market cap(?:italization)?\s+(?:of\s+)?\$?[\d,]+\.?\d*\s*(?:million|billion|trillion|M|B|T)',
                            r'\$[\d,]+\.?\d*\s*(?:million|billion|trillion)\s+market cap',
                        ]
                        for pattern in patterns:
                            match = re.search(pattern, combined_text, re.IGNORECASE)
                            if match:
                                search_data['market_cap'] = match.group(0)
                                print(f"   ✅ Found market cap: {search_data['market_cap']}")
                                break
                    
                    elif key == 'funding':
                        patterns = [
                            r'raised\s+\$?[\d,]+\.?\d*\s*(?:million|billion)',
                            r'\$?[\d,]+\.?\d*\s*(?:million|billion)\s+(?:in\s+)?funding',
                            r'total funding\s+(?:of\s+)?\$?[\d,]+\.?\d*\s*(?:million|billion)',
                        ]
                        for pattern in patterns:
                            match = re.search(pattern, combined_text, re.IGNORECASE)
                            if match:
                                search_data['funding_raised'] = match.group(0)
                                print(f"   ✅ Found funding: {search_data['funding_raised']}")
                                break
                    
                    elif key == 'profitability':
                        if 'profitable' in combined_text.lower():
                            search_data['profitability'] = 'Profitable'
                            print(f"   ✅ Found: Profitable")
                        elif 'unprofitable' in combined_text.lower() or 'loss' in combined_text.lower():
                            search_data['profitability'] = 'Unprofitable'
                            print(f"   ✅ Found: Unprofitable")

                    elif key in ['compliance_certs', 'compliance_public']:
                        cert_keywords = [
                            'ISO 27001', 'ISO 9001', 'ISO 45001', 'ISO 14001',
                            'SOC 2', 'SOC2', 'SOC 1',
                            'PCI DSS', 'PCI-DSS',
                            'HIPAA', 'GDPR', 'SOX', 'CCPA', 'CPRA',
                            'FedRAMP', 'HITRUST', 'NIST', 'CMMC', 'CSA STAR',
                            'FDA', 'GMP', 'CPSC'
                        ]
                        found = [c for c in cert_keywords if c.lower() in combined_text.lower()]
                        if found:
                            existing = search_data.get('compliance_found', [])
                            search_data['compliance_found'] = list(set(existing + found))
                            print(f"   ✅ Found compliance mentions: {found}")
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"   ⚠️ Search failed for {key}: {str(e)}")
                continue
        
        # Summary
        print(f"\n   📊 Financial Search Summary:")
        print(f"      Revenue: {search_data.get('revenue') or '❌'}")
        print(f"      Quarterly: {search_data.get('quarterly_revenue') or '❌'}")
        print(f"      Growth: {search_data.get('revenue_growth') or '❌'}")
        print(f"      Market Cap: {search_data.get('market_cap') or '❌'}")
        print(f"      Funding: {search_data.get('funding_raised') or '❌'}")
        print(f"      Profitability: {search_data.get('profitability') or '❌'}")
        
        return search_data
    
    def scrape_company_website(self, domain: str) -> Dict[str, Any]:
        """Basic website scraping - NO COMPLIANCE SCANNING"""
        print(f"🌐 Scraping {domain}...")
        
        scraped_data = {
            'title': None,
            'description': None,
            'about_text': None,
            'contact_email': None,
            'social_links': {},
            'success': False
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(f"https://{domain}", headers=headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Title
                title_tag = soup.find('title')
                if title_tag:
                    scraped_data['title'] = title_tag.text.strip()
                
                # Meta description
                meta_desc = soup.find('meta', attrs={'name': 'description'}) or \
                           soup.find('meta', attrs={'property': 'og:description'})
                if meta_desc:
                    scraped_data['description'] = meta_desc.get('content', '').strip()
                
                # Extract main content
                main_content = []
                for tag in ['h1', 'h2', 'p']:
                    elements = soup.find_all(tag, limit=15)
                    for elem in elements:
                        text = elem.get_text().strip()
                        if len(text) > 30 and len(text) < 500:
                            main_content.append(text)
                
                scraped_data['about_text'] = ' | '.join(main_content[:10])
                
                # Extract email
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
                if emails:
                    scraped_data['contact_email'] = emails[0]
                
                # Extract social links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if 'linkedin.com' in href:
                        scraped_data['social_links']['linkedin'] = href
                    elif 'twitter.com' in href or 'x.com' in href:
                        scraped_data['social_links']['twitter'] = href
                    elif 'facebook.com' in href:
                        scraped_data['social_links']['facebook'] = href
                
                scraped_data['success'] = True
                print(f"   ✅ Successfully scraped {domain}")
            
        except Exception as e:
            print(f"   ⚠️ Scraping failed: {str(e)}")
        
        return scraped_data
    
    def get_whois_information(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive WHOIS information"""
        if not domain:
            return {}
        
        print(f"📋 Looking up WHOIS for {domain}...")
        
        try:
            domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
            
            w = None
            
            try:
                import whois
                w = whois.whois(domain)
            except (AttributeError, ImportError):
                pass
            
            if w is None:
                try:
                    import subprocess
                    result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        output = result.stdout.lower()
                        
                        creation_date = None
                        for line in output.split('\n'):
                            if 'creation date' in line or 'created' in line:
                                date_match = re.search(r'(\d{4})', line)
                                if date_match:
                                    creation_date = date_match.group(1)
                                    break
                        
                        return {
                            'registrar': 'Unknown',
                            'creation_date': creation_date,
                            'domain_age_years': datetime.now().year - int(creation_date) if creation_date else 0,
                            'country': 'Unknown'
                        }
                except:
                    pass
            
            if w:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                expiration_date = w.expiration_date if hasattr(w, 'expiration_date') else None
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0] if expiration_date else None

                age = 0
                if creation_date:
                    age = (datetime.now() - creation_date).days // 365

                return {
                    'registrar': w.registrar if hasattr(w, 'registrar') else 'Unknown',
                    'creation_date': str(creation_date).split(' ')[0] if creation_date else 'Unknown',
                    'domain_age_years': age,
                    'country': w.country if hasattr(w, 'country') else 'Unknown',
                    'expiration_date': str(expiration_date).split(' ')[0] if expiration_date else 'Unknown'
                }
            
        except Exception as e:
            print(f"   ⚠️ WHOIS lookup failed: {str(e)}")
        
        return {}
    
    # =================================================================
    # API INTEGRATIONS (Phase 1 - Business Domain)
    # =================================================================
    
    def query_hunter_io(self, domain: str) -> dict:
        """Hunter.io - Email discovery API"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        try:
            config = BUSINESS_DOMAIN_APIS['email_finder']
            if not config['enabled']:
                return {}
            
            print(f"   🔍 Querying Hunter.io for {domain}...")
            url = f"{config['endpoint']}?domain={domain}&api_key={config['api_key']}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                emails = data.get('data', {}).get('emails', [])[:10]
                print(f"   ✅ Hunter.io: Found {len(emails)} emails")
                return {
                    'emails': emails,
                    'total': data.get('data', {}).get('total', 0),
                    'pattern': data.get('data', {}).get('pattern', ''),
                    'organization': data.get('data', {}).get('organization', '')
                }
            else:
                print(f"   ⚠️ Hunter.io: HTTP {response.status_code}")
        except Exception as e:
            print(f"   ❌ Hunter.io error: {e}")
        return {}
    
    def query_hostio(self, domain: str) -> dict:
        """Host.io - Domain metadata API"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        try:
            config = BUSINESS_DOMAIN_APIS['domain_info']
            
            if not config.get('enabled'):
                return {}
            
            logger.info(f"Querying Host.io for {domain}...")
            
            url = f"{config['endpoint']}{domain}"
            params = {'token': config['api_key']}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                web_info = data.get('web', {})
                dns_info = data.get('dns', {})
                ipinfo = data.get('ipinfo', {})
                related = data.get('related', {})
                
                logger.info(f"✅ Host.io: Rank {web_info.get('rank', 0)}")
                
                return {
                    'status': 'success',
                    'domain': domain,
                    'web': web_info,
                    'dns': dns_info,
                    'ipinfo': ipinfo,
                    'related': related
                }
            
            else:
                logger.warning(f"Host.io: HTTP {response.status_code}")
                return {'status': 'error', 'error': f'HTTP {response.status_code}'}
        
        except Exception as e:
            logger.error(f"Host.io error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def query_abstractapi_company(self, domain: str) -> dict:
        """AbstractAPI Company Enrichment - PRIMARY SOURCE FOR INDUSTRY & EMPLOYEES"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        try:
            config = BUSINESS_DOMAIN_APIS['company_enrichment']
            if not config['enabled']:
                return {}
            
            print(f"   🔍 Querying AbstractAPI Company for {domain}...")
            url = f"{config['endpoint']}?api_key={config['api_key']}&domain={domain}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ AbstractAPI: Got company data")
                
                # This is the PRIMARY source for industry and employees
                return {
                    'name': data.get('name', ''),
                    'domain': data.get('domain', ''),
                    'country': data.get('country', ''),
                    'locality': data.get('locality', ''),
                    'employees_count': data.get('employees_count', 'Unknown'),  # PRIMARY EMPLOYEE SOURCE
                    'industry': data.get('industry', 'Unknown'),  # PRIMARY INDUSTRY SOURCE
                    'year_founded': data.get('year_founded', 'Unknown'),  # PRIMARY FOUNDED SOURCE
                    'linkedin_url': data.get('linkedin_url', ''),
                    'status': 'success'
                }
            else:
                print(f"   ⚠️ AbstractAPI: HTTP {response.status_code}")
                return {'status': 'error'}
        except Exception as e:
            print(f"   ❌ AbstractAPI error: {e}")
            return {'status': 'error', 'error': str(e)}

    def consolidate_industry(self, abstractapi_industry: str, ai_suggested_industry: str) -> str:
        """
        Consolidate industry from AbstractAPI and AI
        Priority: AbstractAPI > AI
        """
        if abstractapi_industry and abstractapi_industry != 'Unknown':
            return abstractapi_industry
        elif ai_suggested_industry and ai_suggested_industry != 'Unknown':
            return ai_suggested_industry
        else:
            return 'Unknown'
    
    def consolidate_founded_year(self, abstract_year: str, whois_age: int, scraped_year: str, search_year: str) -> str:
        """
        Consolidate founded year from multiple sources
        Priority: AbstractAPI > Search > Scraped > WHOIS estimation
        """
        # AbstractAPI is most reliable
        if abstract_year and abstract_year != 'Unknown':
            return str(abstract_year)
        
        # Search results next
        if search_year:
            return search_year
        
        # Scraped data
        if scraped_year:
            return scraped_year
        
        # WHOIS estimation (least reliable)
        if whois_age > 0:
            return str(datetime.now().year - whois_age)
        
        return 'Unknown'

    def analyze_with_gemini(self, company_name: str, domain: str, whois_data: Dict, 
                           scraped_data: Dict, search_data: Dict, 
                           abstractapi_data: Dict) -> Dict[str, Any]:
        """
        AI analysis with UPDATED PROMPT:
        - NO compliance web scraping
        - AI suggests compliance based on industry/country/services
        - Consolidate industry from AbstractAPI
        - Remove threat_level
        - No employees in financial section
        """
        
        print(f"🤖 Running AI analysis with all collected data...")
        
        # Get consolidated founded year
        domain_age = whois_data.get('domain_age_years', 0)
        scraped_founded = scraped_data.get('founded', None)
        search_founded = search_data.get('founded', None)
        abstract_founded = abstractapi_data.get('year_founded', 'Unknown')
        
        consolidated_founded = self.consolidate_founded_year(
            abstract_founded, domain_age, scraped_founded, search_founded
        )
        
        # Get industry from AbstractAPI (primary source)
        abstract_industry = abstractapi_data.get('industry', 'Unknown')
        
        def _val(v, fallback='Not found publicly'):
            return v if v else fallback

        compliance_found = search_data.get('compliance_found', [])
        is_public = bool(search_data.get('ticker'))

        context = f"""
**COMPANY IDENTIFICATION:**
- Name: {company_name}
- Domain: {domain}
- Domain Age: {domain_age} years
- Founded Year (Consolidated): {consolidated_founded}

**ABSTRACTAPI COMPANY DATA (PRIMARY SOURCE):**
- Industry: {abstract_industry} (USE THIS AS PRIMARY INDUSTRY)
- Employees: {abstractapi_data.get('employees_count', 'Unknown')}
- Country: {abstractapi_data.get('country', 'Unknown')}
- Year Founded: {abstract_founded}

**WEB SCRAPING DATA:**
- Website Title: {scraped_data.get('title', 'N/A')}
- Description: {scraped_data.get('description', 'N/A')}
- About Text: {scraped_data.get('about_text', 'N/A')[:500]}

**GOOGLE SEARCH FINANCIAL RESULTS:**
- Revenue: {_val(search_data.get('revenue'))}
- Quarterly Revenue: {_val(search_data.get('quarterly_revenue'))}
- Revenue Growth: {_val(search_data.get('revenue_growth'))}
- Market Cap: {_val(search_data.get('market_cap'))}
- Funding Raised: {_val(search_data.get('funding_raised'))}
- Profitability: {_val(search_data.get('profitability'))}
- Company Type: {'PUBLIC' if is_public else 'PRIVATE (no stock exchange listing found)'}
- Ticker Symbol: {_val(search_data.get('ticker'), 'N/A - Private company')}
- Headquarters: {_val(search_data.get('headquarters'))}

**RAW GOOGLE SEARCH TEXT FOR CEO (extract the CEO name from this):**
{search_data.get('ceo_raw_text', 'No data')[:600]}

**RAW GOOGLE SEARCH TEXT FOR FOUNDER (extract the founder name from this):**
{search_data.get('founder_raw_text', 'No data')[:600]}

**HUNTER.IO CEO HINT (if found):**
{_val(search_data.get('ceo'), 'Not found in Hunter.io this run')}

**PUBLICLY FOUND COMPLIANCE/CERTIFICATIONS (from web search):**
{', '.join(compliance_found) if compliance_found else 'None found in public search results'}
"""
        
        prompt = f"""You are a senior business intelligence analyst and regulatory compliance expert. Analyze this company and provide comprehensive insights.

{context}

**CRITICAL INSTRUCTIONS:**

1. **INDUSTRY CLASSIFICATION:**
   - PRIMARY SOURCE: Use AbstractAPI industry: "{abstract_industry}"
   - If AbstractAPI says "Unknown", infer from description/services
   - BE SPECIFIC: "Healthcare IT" not just "Healthcare"

2. **FOUNDED YEAR:**
   - USE CONSOLIDATED: {consolidated_founded}
   - Do NOT recalculate from domain age

3. **CEO & FOUNDER EXTRACTION:**
   - Read the RAW GOOGLE SEARCH TEXT FOR CEO above carefully
   - PRIORITY ORDER for current CEO (highest to lowest reliability):
     1. Structured patterns like "(ceo)", "position: CEO", or "CEO:" from business databases (RocketReach, ZoomInfo, LinkedIn) — MOST RELIABLE
     2. Hunter.io hint if provided — treat as strong signal
     3. Direct sentence like "X is the CEO of Company" — only use if from a reputable source
     4. Your own knowledge about this company
   - FOUNDER vs CEO: The FOUNDER and CEO are USUALLY DIFFERENT people
     - If someone appears as "Founder" in the FOUNDER raw text, do NOT also list them as current CEO unless you see explicit recent evidence they currently serve as CEO
     - Cross-check: if the same name appears as Founder AND as CEO, default to treating them as Founder only — find the actual current CEO from other mentions in the CEO raw text
   - For FOUNDER: Read the RAW GOOGLE SEARCH TEXT FOR FOUNDER carefully
     - ONLY use someone as founder if the text explicitly says "founded by X", "X founded the company", or "X is the founder"
     - DO NOT confuse early/first CEO with founder — "held CEO position since the company started" does NOT mean founder
     - A person who was the first CEO is NOT the founder unless explicitly stated
   - NEVER output the same name for both CEO and founder unless certain it is the same person in both roles right now
   - NEVER output the string "None" — if truly unknown write "Not publicly available"

4. **FINANCIAL DATA:**
   - Use search results provided above
   - DO NOT include employee count in financial section
   - Employee data is in AbstractAPI section only

4. **REGULATORY COMPLIANCE:**
   - FIRST check: Publicly found certifications from search = [{', '.join(compliance_found) if compliance_found else 'None'}]
   - If certifications were found publicly, list them as "confirmed_public": true
   - THEN add AI-suggested compliance based on industry/country (label these "ai_suggested": true)
   - Keep the two groups clearly separated in your response
   - Data protection by country (US → CCPA/CPRA, EU → GDPR, etc.)

5. **THREAT INTELLIGENCE:**
   - DO NOT include "threat_level" field
   - APT groups listed must be labelled as AI-SUGGESTED based on industry, NOT verified threat intelligence
   - Focus on critical assets the company should protect

6. **BE SPECIFIC:**
   ❌ WRONG: "Not available"
   ✅ RIGHT: "$196.54 million (FY 2024)" or use search results

**REQUIRED OUTPUT - VALID JSON ONLY:**

{{
    "company_overview": {{
        "primary_business": "SPECIFIC description",
        "industry_vertical": "USE ABSTRACTAPI: {abstract_industry} or infer if Unknown",
        "business_model": "B2B / B2C / SaaS / Marketplace",
        "founded_year": "{consolidated_founded}",
        "headquarters": "Use search results or infer",
        "company_maturity": "Startup / Growth / Mature",
        "company_size": "Based on AbstractAPI employees"
    }},
    "financial_intelligence": {{
        "annual_revenue": "{search_data.get('revenue') or 'Not found publicly'}",
        "quarterly_revenue": "{search_data.get('quarterly_revenue') or 'N/A'}",
        "revenue_year": "2024",
        "revenue_growth": "{search_data.get('revenue_growth') or 'N/A'}",
        "company_type": "Public (Ticker: XXX) OR Private",
        "is_public": true/false,
        "ticker_symbol": "{search_data.get('ticker') or 'N/A'}",
        "market_cap": "{search_data.get('market_cap') or 'N/A'}",
        "funding_raised": "{search_data.get('funding_raised') or 'N/A'}",
        "profitability": "{search_data.get('profitability') or 'Not found publicly'}"
    }},
    "services_and_products": {{
        "primary_products": ["Actual product names"],
        "service_categories": ["Specific service types"],
        "key_offerings": ["Main offerings"]
    }},
    "customer_base": {{
        "target_customers": ["Specific customer types"],
        "customer_segments": ["Enterprise / SMB / Consumer"],
        "geographic_markets": ["Countries/regions"],
        "notable_clients": ["If publicly available"]
    }},
    "leadership": {{
        "ceo": "Extract CURRENT CEO from raw search text above",
        "founder": "Extract founder from raw search text above"
    }},
    "threat_intelligence": {{
        "industry_apt_groups": ["APT groups targeting this industry"],
        "critical_assets": ["Most valuable data/IP"]
    }},
    "regulatory_compliance": {{
        "confirmed_public": [{{"name": "ISO 27001", "confirmed_public": true}}],
        "ai_suggested": [{{"name": "SOC 2", "ai_suggested": true, "rationale": "Common for SaaS companies"}}],
        "data_protection_requirements": ["Based on geography and data types"],
        "compliance_rationale": "Brief explanation of why these apply"
    }},
    "data_quality": {{
        "revenue_source": "Search results / AI knowledge / Unknown",
        "confidence_score": 1-10
    }}
}}

**RETURN ONLY THE JSON - NO MARKDOWN, NO EXPLANATIONS**
"""

        try:
            if self.use_gemini:
                raw = _gemini_call(prompt, max_tokens=8192, temperature=0.1)
                if not raw:
                    return self._create_fallback_response(
                        company_name, domain, whois_data, scraped_data,
                        search_data, abstractapi_data, consolidated_founded
                    )

                ai_text = raw.strip()
                
                # Clean JSON
                if '```json' in ai_text:
                    ai_text = ai_text.split('```json')[1].split('```')[0]
                elif '```' in ai_text:
                    parts = ai_text.split('```')
                    if len(parts) >= 3:
                        ai_text = parts[1]
                
                ai_text = ai_text.strip()
                parsed = json.loads(ai_text)
                
                print("   ✅ AI analysis completed successfully")
                return parsed
                
            else:
                print("   ⚠️ Gemini not available, using fallback")
                return self._create_fallback_response(
                    company_name, domain, whois_data, scraped_data, 
                    search_data, abstractapi_data, consolidated_founded
                )
                
        except json.JSONDecodeError as e:
            print(f"   ❌ JSON parsing failed: {e}")
            print(f"   Raw response: {ai_text[:200]}...")
            return self._create_fallback_response(
                company_name, domain, whois_data, scraped_data, 
                search_data, abstractapi_data, consolidated_founded
            )
        except Exception as e:
            print(f"   ❌ AI analysis failed: {str(e)}")
            return self._create_fallback_response(
                company_name, domain, whois_data, scraped_data, 
                search_data, abstractapi_data, consolidated_founded
            )
    
    def _create_fallback_response(self, company_name: str, domain: str, whois_data: Dict,
                                 scraped_data: Dict, search_data: Dict, 
                                 abstractapi_data: Dict, consolidated_founded: str) -> Dict:
        """Fallback response when AI fails"""
        print("   📝 Creating fallback response...")
        
        abstract_industry = abstractapi_data.get('industry', 'Unknown')
        
        return {
            "company_overview": {
                "primary_business": scraped_data.get('description', f"Company at {domain}"),
                "industry_vertical": abstract_industry,
                "business_model": "B2B/B2C",
                "founded_year": consolidated_founded,
                "headquarters": search_data.get('headquarters', abstractapi_data.get('country', 'Unknown')),
                "company_maturity": "Mature" if whois_data.get('domain_age_years', 0) > 10 else "Growth",
                "company_size": "Unknown"
            },
            "financial_intelligence": {
                "annual_revenue": search_data.get('revenue', 'Data not available'),
                "quarterly_revenue": search_data.get('quarterly_revenue', 'N/A'),
                "revenue_year": "2024",
                "revenue_growth": search_data.get('revenue_growth', 'N/A'),
                "company_type": f"{'Public' if search_data.get('ticker') else 'Private'}",
                "is_public": bool(search_data.get('ticker')),
                "ticker_symbol": search_data.get('ticker', 'N/A'),
                "market_cap": search_data.get('market_cap', 'N/A'),
                "funding_raised": search_data.get('funding_raised', 'N/A'),
                "profitability": search_data.get('profitability', 'Unknown')
            },
            "services_and_products": {
                "primary_products": [],
                "service_categories": [],
                "key_offerings": []
            },
            "customer_base": {
                "target_customers": [],
                "customer_segments": [],
                "geographic_markets": [],
                "notable_clients": []
            },
            "leadership": {
                "ceo": search_data.get('ceo', 'Unknown'),
                "founder": search_data.get('founder', 'Unknown')
            },
            "threat_intelligence": {
                "industry_apt_groups": [],
                "critical_assets": ["Customer data", "IP", "Financial records"]
            },
            "regulatory_compliance": {
                "confirmed_public": [{"name": c, "confirmed_public": True} for c in search_data.get('compliance_found', [])],
                "ai_suggested": [],
                "data_protection_requirements": [],
                "compliance_rationale": "AI analysis unavailable — showing only publicly found certifications"
            },
            "data_quality": {
                "revenue_source": "Search results" if search_data.get('revenue') else "Unknown",
                "confidence_score": 4
            }
        }
    
    def analyze_company(self, company_name: str, domain: str = None) -> Dict[str, Any]:
        """
        Main analysis function - UPDATED VERSION
        Focus: Financial intelligence + AI-based compliance recommendations
        """
        
        if '.' in company_name and not domain:
            domain = company_name
            company_name = company_name.split('.')[0].title()
        
        print("\n" + "="*70)
        print(f"ANALYZING: {company_name} ({domain})")
        print("="*70)
        
        # Step 1: WHOIS (foundational data)
        whois_data = self.get_whois_information(domain) if domain else {}
        
        # Step 2: Web Scraping (basic info only)
        scraped_data = self.scrape_company_website(domain) if domain else {}

        # Step 2.5: AbstractAPI early — get accurate company name BEFORE Serper searches
        print(f"🏢 Getting company name from AbstractAPI...")
        abstractapi_data = self.query_abstractapi_company(domain) if domain else {}

        # Company name priority:
        # 1. AbstractAPI name (most reliable — dedicated company data API)
        # 2. og:site_name / page title split (free, from scraping)
        # 3. Domain split (last resort)
        abstract_name = abstractapi_data.get('name', '')
        if abstract_name:
            domain_root = domain.split('.')[0].lower()
            # If abstract name is a short prefix of the domain (e.g. "Domo" in "domochemicals"),
            # the domain contains extra context — build a richer name to avoid search ambiguity
            if (len(abstract_name) < 10
                    and domain_root.startswith(abstract_name.lower().replace(' ', ''))
                    and len(domain_root) > len(abstract_name.replace(' ', ''))):
                suffix = domain_root[len(abstract_name.replace(' ', '')):].strip()
                company_name = f"{abstract_name} {suffix.title()}"
                print(f"   ✅ Company name refined from domain context: '{company_name}'")
            else:
                company_name = abstract_name
                print(f"   ✅ Company name from AbstractAPI: '{company_name}'")
        else:
            # Fallback: try page title
            page_title = scraped_data.get('title', '')
            if page_title:
                for sep in ['|', '-', ':']:
                    parts = page_title.split(sep)
                    last = parts[-1].strip() if len(parts) > 1 else ''
                    clean = re.sub(r'[™®©]', '', last).strip()
                    if 3 < len(clean) < 50 and clean:
                        company_name = clean
                        print(f"   ✅ Company name from page title: '{company_name}'")
                        break
            else:
                print(f"   ⚠️ Using domain-derived name: '{company_name}'")

        # Step 3: Google Search — now uses accurate company name
        search_data = self.search_google_for_financial_data(company_name, domain) if domain else {}

        # Step 4: API INTEGRATIONS
        print("\n" + "="*70)
        print("🔹 PHASE 1: API INTEGRATIONS")
        print("="*70)

        hunter_data = self.query_hunter_io(domain)
        hostio_data = self.query_hostio(domain)
        # AbstractAPI already called above — reuse the result

        logger.info("✅ API queries completed")

        # Extract CEO from Hunter.io if Serper didn't find one
        # Hunter.io is more reliable — it finds the actual person with verified position
        if not search_data.get('ceo'):
            for email_obj in hunter_data.get('emails', []):
                position_raw = (email_obj.get('position_raw') or email_obj.get('position') or '').lower()
                dept = (email_obj.get('department') or '').lower()
                seniority = (email_obj.get('seniority') or '').lower()
                if 'chief executive' in position_raw or position_raw == 'ceo':
                    full_name = f"{email_obj.get('first_name', '')} {email_obj.get('last_name', '')}".strip()
                    if full_name:
                        search_data['ceo'] = full_name
                        print(f"   ✅ CEO from Hunter.io: {full_name}")
                        break
                # Fallback: executive department + executive seniority
                if not search_data.get('ceo') and dept == 'executive' and seniority == 'executive':
                    full_name = f"{email_obj.get('first_name', '')} {email_obj.get('last_name', '')}".strip()
                    if full_name:
                        search_data['ceo'] = full_name
                        print(f"   ✅ CEO (exec fallback) from Hunter.io: {full_name}")
                        break

        # HQ fallback: if Serper didn't find headquarters, use AbstractAPI locality + country
        if not search_data.get('headquarters'):
            locality = abstractapi_data.get('locality', '')
            country = abstractapi_data.get('country', '')
            if locality and country:
                search_data['headquarters'] = f"{locality}, {country}"
                print(f"   ✅ HQ from AbstractAPI: {search_data['headquarters']}")
            elif locality:
                search_data['headquarters'] = locality
                print(f"   ✅ HQ from AbstractAPI: {search_data['headquarters']}")

        # Step 5: AI Analysis (with consolidated data)
        ai_analysis = self.analyze_with_gemini(
            company_name, domain, whois_data, scraped_data,
            search_data, abstractapi_data
        )
        
        # Compile final result
        company_data = {
            'name': company_name,
            'domain': domain,
            'whois_data': whois_data,
            'scraped_data': scraped_data,
            'search_data': search_data,
            'ai_analysis': ai_analysis,
            'hunter_io': hunter_data,
            'host_io': hostio_data,
            'abstractapi_company': abstractapi_data,
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        print("="*70)
        print("✅ ANALYSIS COMPLETE")
        print("="*70 + "\n")
        
        return company_data


# Main execution
if __name__ == "__main__":
    analyzer = CompanyIntelligenceAnalyzer()

    # Test with a domain
    test_domain = input("Enter domain to analyze (e.g., google.com): ").strip()
    if test_domain:
        result = analyzer.analyze_company(test_domain.split('.')[0].title(), test_domain)

        # Print summary
        print("\n" + "="*70)
        print("ANALYSIS SUMMARY")
        print("="*70)
        print(json.dumps(result, indent=2, default=str))

        # Save to reports/ folder
        import os
        os.makedirs("reports", exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = test_domain.replace(".", "_")
        out_path = os.path.join("reports", f"{safe}_phase1_domain_{ts}.json")
        with open(out_path, "w", encoding="utf-8") as _f:
            json.dump(result, _f, indent=2, default=str)
        print(f"\n💾 Phase 1 report saved: {out_path}")