"""
Phase 1: Data Extraction Methods
Handles extraction of financial, WHOIS, and web scraping data
"""

import requests
import logging
import re
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
import json

logger = logging.getLogger(__name__)


class DataExtraction:
    """Handles data extraction from various sources"""

    def extract_financial_data_from_html(self, soup: BeautifulSoup, domain: str) -> Dict[str, Any]:
        """Extract financial data from HTML"""
        financial_data = {
            'revenue': None,
            'quarterly_revenue': None,
            'revenue_growth': None,
            'market_cap': None,
            'funding_raised': None,
            'profitability': None,
            'founded': None,
            'employees': None,
            'ticker': None,
            'headquarters': None,
        }

        # Extract from JSON-LD structured data
        for script in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(script.string or '{}')
                items = data if isinstance(data, list) else [data]
                for item in items:
                    self._extract_financial_from_jsonld(item, financial_data)
            except Exception:
                pass

        # Extract from meta tags
        for meta in soup.find_all('meta'):
            name = (meta.get('name') or meta.get('property') or '').lower()
            content = meta.get('content', '')
            if 'revenue' in name and content:
                financial_data['revenue'] = content
            elif 'founded' in name and content:
                financial_data['founded'] = content
            elif 'employee' in name and content:
                financial_data['employees'] = content

        # Extract from visible text using regex patterns
        text = soup.get_text(' ', strip=True)
        if not financial_data['revenue']:
            rev_match = re.search(
                r'(?:annual\s+)?revenue[:\s]+\$?([\d,.]+\s*(?:billion|million|B|M|K)?)',
                text, re.IGNORECASE
            )
            if rev_match:
                financial_data['revenue'] = rev_match.group(1).strip()

        if not financial_data['employees']:
            emp_match = re.search(
                r'(?:number\s+of\s+)?employees?[:\s]+([\d,]+(?:\s*[-–]\s*[\d,]+)?)',
                text, re.IGNORECASE
            )
            if emp_match:
                financial_data['employees'] = emp_match.group(1).strip()

        if not financial_data['founded']:
            found_match = re.search(
                r'(?:founded|established)[:\s]+(?:in\s+)?(\d{4})',
                text, re.IGNORECASE
            )
            if found_match:
                financial_data['founded'] = found_match.group(1)

        return financial_data

    def _extract_financial_from_jsonld(self, data: dict, output: dict):
        """Extract financial data from JSON-LD structured data"""
        if not isinstance(data, dict):
            return

        field_map = {
            'revenue': 'revenue',
            'annualRevenue': 'revenue',
            'marketCap': 'market_cap',
            'marketCapitalization': 'market_cap',
            'foundingDate': 'founded',
            'numberOfEmployees': 'employees',
            'tickerSymbol': 'ticker',
            'address': None,  # handled separately
        }

        for json_key, out_key in field_map.items():
            if json_key in data and out_key and not output.get(out_key):
                output[out_key] = data[json_key]

        # Address → headquarters
        if 'address' in data and isinstance(data['address'], dict):
            addr = data['address']
            parts = [addr.get('addressLocality'), addr.get('addressRegion'), addr.get('addressCountry')]
            hq = ', '.join(p for p in parts if p)
            if hq and not output.get('headquarters'):
                output['headquarters'] = hq

        # Recurse into nested objects
        for val in data.values():
            if isinstance(val, dict):
                self._extract_financial_from_jsonld(val, output)

    def scrape_company_website(self, domain: str) -> Dict[str, Any]:
        """Scrape company website for information"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; BSI-Scanner/1.0)'}
            url = f"https://{domain}"
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Extract description
                description = ''
                desc_meta = soup.find('meta', attrs={'name': 'description'}) or \
                            soup.find('meta', attrs={'property': 'og:description'})
                if desc_meta:
                    description = desc_meta.get('content', '')

                # Extract keywords
                keywords = ''
                kw_meta = soup.find('meta', attrs={'name': 'keywords'})
                if kw_meta:
                    keywords = kw_meta.get('content', '')

                # Extract financial data
                financial = self.extract_financial_data_from_html(soup, domain)

                # Extract social links
                social_links = {}
                for a in soup.find_all('a', href=True):
                    href = a['href'].lower()
                    if 'linkedin.com' in href:
                        social_links['linkedin'] = a['href']
                    elif 'twitter.com' in href or 'x.com' in href:
                        social_links['twitter'] = a['href']
                    elif 'facebook.com' in href:
                        social_links['facebook'] = a['href']

                return {
                    'success': True,
                    'title': soup.title.string.strip() if soup.title and soup.title.string else None,
                    'description': description,
                    'keywords': keywords,
                    'content_length': len(response.content),
                    'final_url': response.url,
                    'financial_data': financial,
                    'social_links': social_links,
                }
            return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Website scraping failed for {domain}: {str(e)}")
            return {'success': False, 'error': str(e)}

    def get_whois_information(self, domain: str) -> Dict[str, Any]:
        """
        Get WHOIS/registration information for a domain.
        Uses RDAP (modern WHOIS replacement) via HTTP — no CLI required.
        Falls back to a second RDAP endpoint if the first fails.
        """
        # Strip subdomains down to registrable domain (e.g. sub.example.com → example.com)
        parts = domain.lower().strip().split('.')
        registrable = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

        rdap_endpoints = [
            f"https://rdap.org/domain/{registrable}",
            f"https://rdap.iana.org/domain/{registrable}",
        ]

        for url in rdap_endpoints:
            try:
                resp = requests.get(
                    url,
                    timeout=15,
                    headers={'Accept': 'application/rdap+json, application/json'},
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                return self._parse_rdap(data, registrable)

            except requests.exceptions.Timeout:
                logger.warning(f"RDAP timeout for {registrable} at {url}")
            except Exception as e:
                logger.warning(f"RDAP failed for {registrable} at {url}: {e}")

        logger.error(f"All RDAP lookups failed for {registrable}")
        return {'error': 'WHOIS lookup failed (all RDAP endpoints unreachable)', 'domain': registrable}

    def _parse_rdap(self, data: dict, domain: str) -> Dict[str, Any]:
        """Parse RDAP JSON response into a flat WHOIS-style dict."""
        from datetime import datetime, timezone

        result = {
            'domain': data.get('ldhName', domain).lower(),
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'organization': None,
            'country': None,
            'name_servers': [],
            'status': None,
            'domain_age_years': None,
        }

        # ── Events → dates ────────────────────────────────────────────────
        for event in data.get('events', []):
            action = event.get('eventAction', '').lower()
            date   = event.get('eventDate', '')[:10]   # keep YYYY-MM-DD
            if 'registration' in action:
                result['creation_date'] = date
            elif 'expiration' in action:
                result['expiration_date'] = date
            elif 'last changed' in action or 'last update' in action and 'rdap' not in action:
                result['updated_date'] = date

        # ── Domain age ────────────────────────────────────────────────────
        if result['creation_date']:
            try:
                created = datetime.strptime(result['creation_date'], '%Y-%m-%d')
                result['domain_age_years'] = round(
                    (datetime.now() - created).days / 365.25, 1
                )
            except Exception:
                pass

        # ── Entities → registrar, org, country ───────────────────────────
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            vcard = entity.get('vcardArray', [None, []])[1]

            # Extract fn (full name) from vcard
            fn = ''
            org_vcard = ''
            country_vcard = ''
            for field in vcard:
                if not isinstance(field, list):
                    continue
                fname = field[0] if field else ''
                fval  = field[3] if len(field) > 3 else ''
                if fname == 'fn':
                    fn = str(fval)
                elif fname == 'org':
                    org_vcard = str(fval)
                elif fname == 'country-name':
                    country_vcard = str(fval)
                elif fname == 'adr':
                    # adr value is a list: [pobox, ext, street, city, region, postal, country]
                    if isinstance(fval, list) and len(fval) >= 7:
                        country_vcard = country_vcard or str(fval[6])

            if 'registrar' in roles and fn:
                result['registrar'] = fn
            if 'registrant' in roles:
                result['organization'] = org_vcard or fn or result['organization']
                result['country'] = country_vcard or result['country']

        # ── Nameservers ───────────────────────────────────────────────────
        result['name_servers'] = [
            ns.get('ldhName', '').lower()
            for ns in data.get('nameservers', [])
            if ns.get('ldhName')
        ]

        # ── Status ────────────────────────────────────────────────────────
        statuses = data.get('status', [])
        result['status'] = ', '.join(statuses) if statuses else None

        return result
