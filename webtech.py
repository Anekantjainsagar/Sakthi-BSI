import requests
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime
import sys
import certifi
import os
import time
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webtech-phase3")

# ✅ ADD NEW API CONFIG IMPORT
try:
    from bsi_api_config import APPLICATION_LANDSCAPE_APIS
    API_CONFIG_AVAILABLE = True
    print("✅ bsi_api_config loaded - Phase 3 APIs enabled")
except ImportError:
    API_CONFIG_AVAILABLE = False
    print("⚠️ bsi_api_config not found - Phase 3 APIs disabled")

class CompleteBSIScanner:
    def __init__(self, domain):
        self.domain = domain.replace('http://', '').replace('https://', '').strip('/')
        self.base_url = f"https://{self.domain}"
        self.results = {
            "domain": self.domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "1_application_discovery": {},
            "2_web_server_stack": {},
            "3_erp_sap_detection": {},
            "4_third_party_software": {},
            "5_code_repositories": {},
            "6_outdated_software": {},
            "7_security_posture": {},
            "8_api_discovery": {},
            "9_database_detection": {}
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        }
        self.html_content = None
        self.soup = None
        self.response = None
        self.session = requests.Session()
        self.session.verify = certifi.where()

    def run_full_scan(self):
        print(f"\n{'='*80}")
        print(f"BSI STAGE 3 - COMPLETE OSINT SCANNER")
        print(f"Domain: {self.domain}")
        print(f"{'='*80}\n")
        
        if not self.fetch_website():
            print("Cannot access website. Exiting...")
            return self.results
        
        self.application_discovery()
        self.web_server_technology_stack()
        self.erp_sap_detection()
        self.third_party_software_inventory()
        self.code_repository_analysis()
        self.outdated_software_detection()
        self.security_posture_analysis()
        self.api_endpoint_discovery()
        self.database_detection()
        # ✅ ADD THESE NEW API CALLS HERE
        
        # Extract IP addresses from earlier results (if available)
        ip_addresses = []
        app_disc = self.results.get('1_application_discovery', {})
        # Try to get IPs from your app if Phase 2 ran
        # For now, we'll use empty list or resolve domain
        try:
            import socket
            ip = socket.gethostbyname(self.domain)
            ip_addresses = [ip]
        except:
            pass
        
        # Call NEW API methods
        if ip_addresses:
            threat_data = self.query_threat_intel_apis(ip_addresses)
            if threat_data:
                self.results['10_threat_intelligence'] = threat_data
            
            leak_data = self.query_leak_detection_apis(self.domain, ip_addresses)
            if leak_data:
                self.results['11_leak_detection'] = leak_data
        
        s3_data = self.query_grayhatwarfare(self.domain)
        if s3_data:
            self.results['12_s3_exposure'] = s3_data

        # ✅ ADD THIS - Store WhatCMS in web server stack (phase 2)
        cms_data = self.query_whatcms(self.domain)
        if cms_data and cms_data.get('status') == 'success':
            webtech = self.results.get('2_web_server_stack', {})
            webtech['whatcms_api'] = cms_data
            # Merge WhatCMS CMS detections into cms list (WhatCMS is more reliable)
            cms_names_from_api = [
                t['name'] for t in cms_data.get('technologies', [])
                if 'CMS' in t.get('categories', []) or 'Other CMS' in t.get('categories', [])
            ]
            if cms_names_from_api:
                current_cms = webtech.get('cms', [])
                # Remove false local detections if WhatCMS disagrees
                for api_cms in cms_names_from_api:
                    if api_cms not in current_cms:
                        current_cms.append(api_cms)
                # If WhatCMS found a different CMS, clear conflicting local ones
                local_only = [c for c in current_cms if c not in cms_names_from_api]
                for c in local_only:
                    if c in current_cms:
                        current_cms.remove(c)
                        print(f"   ℹ️ Removed false-positive CMS '{c}' — WhatCMS identifies {cms_names_from_api}")
                webtech['cms'] = current_cms
                # Update cms_versions with WhatCMS versions
                for t in cms_data.get('technologies', []):
                    if t['name'] in cms_names_from_api and t.get('version'):
                        webtech.setdefault('cms_versions', {})[t['name']] = t['version']
                webtech['all_detected'] = (
                    webtech.get('cms', []) +
                    webtech.get('frameworks', []) +
                    webtech.get('javascript_libraries', []) +
                    webtech.get('analytics', []) +
                    webtech.get('cdn', []) +
                    webtech.get('fonts', [])
                )
            self.results['2_web_server_stack'] = webtech
        
        # ✅ ADD THIS NEW CALL (Add before the final return)
        pastebin_data = self.query_pastebin_leaks(self.domain)
        if pastebin_data and pastebin_data.get('status') in ['success', 'no_results']:
            # Ensure leak_detection dictionary exists
            if '11_leak_detection' not in self.results:
                self.results['11_leak_detection'] = {}
            
            # Store PasteBin data in leak detection section
            self.results['11_leak_detection']['pastebin_search'] = pastebin_data


        # ✅ NEW: Project Honey Pot IP Reputation Check
        honeypot_data = self.query_projecthoneypot(self.domain)
        if honeypot_data and honeypot_data.get('status') == 'active':
            # Store in threat intelligence section (NOT leak detection)
            if '10_threat_intelligence' not in self.results:
                self.results['10_threat_intelligence'] = {}
            self.results['10_threat_intelligence']['honeypot'] = honeypot_data

        # ✅ IntelligenceX Dark Web Search
        intelx_data = self.query_intelligencex(self.domain)
        if intelx_data and intelx_data.get('status') == 'active':
            if '11_leak_detection' not in self.results:
                self.results['11_leak_detection'] = {}
            self.results['11_leak_detection']['intelx'] = intelx_data

        # ✅ ENHANCEMENT: Organize additional threat intel APIs under proper sections
        if self.domain:
            vt_result = self.check_virustotal_v2(domain=self.domain)
            if vt_result and vt_result.get('status') != 'not_configured':
                if '10_threat_intelligence' not in self.results:
                    self.results['10_threat_intelligence'] = {}
                self.results['10_threat_intelligence']['virustotal'] = vt_result

            pd_result = self.check_pulsedive_threat(domain=self.domain)
            if pd_result and pd_result.get('status') != 'not_configured':
                if '10_threat_intelligence' not in self.results:
                    self.results['10_threat_intelligence'] = {}
                self.results['10_threat_intelligence']['pulsedive'] = pd_result

        # ViewDNS co-hosted domains (infrastructure discovery)
        if ip_addresses:
            cohost = []
            for ip in ip_addresses[:2]:
                viewdns_result = self.check_viewdns_reverse_ip(ip)
                if viewdns_result:
                    cohost.append(viewdns_result)
            if cohost:
                if '1_application_discovery' not in self.results:
                    self.results['1_application_discovery'] = {}
                self.results['1_application_discovery']['co_hosted_domains'] = cohost


        return self.results

    def fetch_website(self):
        try:
            print("Fetching website content...")
            # Try HTTPS first
            try:
                self.response = requests.get(
                    self.base_url,
                    headers=self.headers,
                    timeout=30,
                    verify=False,
                    allow_redirects=True
                )
            except:
                # Fallback to HTTP if HTTPS fails
                print("HTTPS failed, trying HTTP...")
                self.base_url = f"http://{self.domain}"
                self.response = requests.get(
                    self.base_url,
                    headers=self.headers,
                    timeout=30,
                    verify=False,
                    allow_redirects=True
                )
        
            self.html_content = self.response.text
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            print(f"Website loaded ({len(self.html_content)} bytes)\n")
            return True
        except Exception as e:
            print(f"Error: {str(e)}\n")
            return False

    def application_discovery(self):
        print("="*80)
        print("[1] APPLICATION DISCOVERY")
        print("="*80)
        
        try:
            app_info = {
        "status": "Active" if self.response.status_code == 200 else "Inactive",
        "status_code": self.response.status_code,
        "server": self.response.headers.get('Server', 'Not disclosed'),
        "server_version": None,  # This will be populated below
        "powered_by": self.response.headers.get('X-Powered-By', 'Not disclosed'),
        "response_time_ms": int(self.response.elapsed.total_seconds() * 1000),
        "content_length": len(self.html_content),
        "detection_method": "Direct HTTP request + HTML parsing",
        "header_fingerprints": {}  # NEW: Store detailed header fingerprints
            }
            
            server_header = self.response.headers.get('Server', '')
            if server_header:
                version_match = re.search(r'([A-Za-z][A-Za-z0-9\-]*)[/\s](\d+\.\d+\.?\d*)', server_header)
                if version_match:
                    server_name = version_match.group(1)
                    server_version = version_match.group(2)
                    app_info["server_version"] = server_version
                    app_info["server_full"] = f"{server_name} {server_version}"
                    print(f"   Server: {server_name} {server_version}")
                else:
                    # No version in header — store name with explicit "(version unknown)"
                    name_only = re.search(r'^([A-Za-z][A-Za-z0-9\-/. ]+)', server_header)
                    name = name_only.group(1).strip() if name_only else server_header
                    app_info["server_name_only"] = name
                    app_info["server_full"] = name
                    app_info["server_version"] = "unknown"
                    print(f"   Server: {name} (version not disclosed)")

            # ✅ ENHANCEMENT 1: Technology fingerprinting from HTTP headers
            print("\n   [Header Fingerprinting]")
            fingerprints = {}

            # X-Powered-By — extract version separately (e.g. PHP/7.4.3 → name=PHP, version=7.4.3)
            x_powered = self.response.headers.get('X-Powered-By', '')
            if x_powered:
                fingerprints['X-Powered-By'] = x_powered
                xpb_ver = re.search(r'([A-Za-z.]+)[/\s](\d+\.\d+\.?\d*)', x_powered)
                if xpb_ver:
                    fingerprints['X-Powered-By-Name']    = xpb_ver.group(1)
                    fingerprints['X-Powered-By-Version'] = xpb_ver.group(2)
                    print(f"      X-Powered-By: {xpb_ver.group(1)} {xpb_ver.group(2)}")
                else:
                    print(f"      X-Powered-By: {x_powered} (version unknown)")
            
            # X-Generator (CMS version leaks)
            x_generator = self.response.headers.get('X-Generator', '')
            if x_generator:
                fingerprints['X-Generator'] = x_generator
                print(f"      X-Generator: {x_generator}")
            
            # X-AspNet-Version
            x_aspnet = self.response.headers.get('X-AspNet-Version', '')
            if x_aspnet:
                fingerprints['X-AspNet-Version'] = x_aspnet
                print(f"      X-AspNet-Version: {x_aspnet}")
            
            # X-Drupal-Cache, X-Drupal-Dynamic-Cache
            x_drupal = self.response.headers.get('X-Drupal-Cache', '') or self.response.headers.get('X-Drupal-Dynamic-Cache', '')
            if x_drupal:
                fingerprints['X-Drupal'] = x_drupal
                print(f"      X-Drupal: {x_drupal}")
            
            # Via header (proxy/cache versions)
            via = self.response.headers.get('Via', '')
            if via:
                fingerprints['Via'] = via
                print(f"      Via: {via}")
            
            app_info['header_fingerprints'] = fingerprints
            
            if not fingerprints:
                print("      No technology headers detected")
            
            if len(self.html_content) < 5000:
                app_info["possible_bot_block"] = True
                app_info["note"] = "Small HTML size - site may be blocking automated requests"
            else:
                app_info["possible_bot_block"] = False
            
            self.results["1_application_discovery"] = app_info
            
            print(f"\n   Status: {app_info['status']}")
            print(f"   Server: {app_info['server']}")
            if app_info.get('server_version'):
                print(f"   Server Version: {app_info['server_version']}")
            print(f"   Response Time: {app_info['response_time_ms']} ms")
            print(f"   HTML Size: {app_info['content_length']} bytes")
            
            if app_info.get("possible_bot_block"):
                print(f"   WARNING: {app_info['note']}")
            
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def web_server_technology_stack(self):
        print("="*80)
        print("[2] WEB SERVER TECHNOLOGY STACK")
        print("="*80)
        
        try:
            tech_stack = {
                "web_server": self.response.headers.get('Server', 'Unknown'),
                "cms": [],
                "cms_version": None,
                "frameworks": [],
                "javascript_libraries": [],
                "javascript_versions": {},
                "analytics": [],
                "cdn": [],
                "fonts": [],
                "all_detected": []
            }
            
            scripts = self.soup.find_all('script', src=True)
            links = self.soup.find_all('link', href=True)
            
            all_scripts = [s.get('src') for s in scripts]
            all_links = [l.get('href') for l in links]
            
            print(f"\n   Found {len(all_scripts)} scripts and {len(all_links)} links\n")
            
            all_urls = all_scripts + all_links
            all_urls_text = ' '.join(all_urls).lower()
            
            # CMS Detection - FIXED AND STRICT
            print("   [CMS Detection]")
            
            # Check for actual WordPress files in URLs
            wp_files = ['wp-content', 'wp-includes', 'wp-admin', 'wp-json']
            has_wp = any(wp_file in all_urls_text for wp_file in wp_files)
            
            if has_wp:
                tech_stack["cms"].append("WordPress")
                
                # Method 1: Try to get version from generator meta tag (MOST RELIABLE)
                generator = self.soup.find('meta', attrs={'name': 'generator'})
                if generator:
                    gen_content = generator.get('content', '')
                    wp_ver_match = re.search(r'WordPress\s+(\d+\.\d+\.?\d*)', gen_content, re.IGNORECASE)
                    if wp_ver_match:
                        tech_stack["cms_version"] = wp_ver_match.group(1)
                
                # Method 2: Only check ver= in ACTUAL WordPress file URLs
                if not tech_stack["cms_version"]:
                    for url in all_urls:
                        url_lower = url.lower()
                        # Must be a WordPress file AND have ver= parameter
                        if any(wp in url_lower for wp in ['wp-includes/', 'wp-content/']):
                            if 'ver=' in url:
                                version_match = re.search(r'[?&]ver=(\d+\.\d+\.?\d*)', url)
                                if version_match:
                                    version = version_match.group(1)
                                    # Validate WordPress version format
                                    if version[0] in ['4', '5', '6', '7']:
                                        tech_stack["cms_version"] = version
                                        break
                
                # Method 3: Check readme.html
                if not tech_stack["cms_version"]:
                    try:
                        r = requests.get(urljoin(self.base_url, '/readme.html'), headers=self.headers, timeout=5, verify=False)
                        if r.status_code == 200:
                            m = re.search(r'Version\s+(\d+\.\d+\.?\d*)', r.text)
                            if m:
                                tech_stack["cms_version"] = m.group(1)
                    except:
                        pass

                # Method 4: jQuery URL ver= inside wp-includes
                if not tech_stack["cms_version"]:
                    for url in all_urls:
                        if 'wp-includes/js/jquery' in url.lower() and 'ver=' in url:
                            m = re.search(r'[?&]ver=(\d+\.\d+\.?\d*)', url)
                            if m and m.group(1)[0] in ['4','5','6','7']:
                                tech_stack["cms_version"] = m.group(1)
                                break

                # Method 5: RSS feed generator tag
                if not tech_stack["cms_version"]:
                    try:
                        r = requests.get(urljoin(self.base_url, '/feed/'), headers=self.headers, timeout=5, verify=False)
                        if r.status_code == 200:
                            m = re.search(r'<generator>[^<]*WordPress[/ ](\d+\.\d+\.?\d*)', r.text)
                            if m:
                                tech_stack["cms_version"] = m.group(1)
                    except:
                        pass

                print(f"      WordPress {tech_stack['cms_version'] or 'version unknown'}")
            
            if re.search(r'cdn\.shopify|myshopify', all_urls_text):
                tech_stack["cms"].append("Shopify")
                print(f"      Shopify")
            
            if re.search(r'wixstatic|parastorage', all_urls_text):
                tech_stack["cms"].append("Wix")
                print(f"      Wix")

            # Drupal — with version extraction
            gen_tag = self.soup.find('meta', attrs={'name': 'generator'})
            gen_content = gen_tag.get('content', '') if gen_tag else ''
            if re.search(r'drupal|sites/default/files|/misc/drupal\.js', all_urls_text) or 'drupal' in gen_content.lower():
                tech_stack["cms"].append("Drupal")
                drupal_ver = re.search(r'Drupal\s+(\d+\.\d*\.?\d*)', gen_content, re.I)
                if not drupal_ver:
                    # Try CHANGELOG.txt
                    try:
                        r = requests.get(urljoin(self.base_url, '/CHANGELOG.txt'), headers=self.headers, timeout=5, verify=False)
                        if r.status_code == 200:
                            drupal_ver = re.search(r'Drupal\s+(\d+\.\d+\.?\d*)', r.text, re.I)
                    except:
                        pass
                ver = drupal_ver.group(1) if drupal_ver else 'version unknown'
                tech_stack["cms_versions"] = tech_stack.get("cms_versions", {})
                tech_stack["cms_versions"]["Drupal"] = ver
                print(f"      Drupal {ver}")

            # Joomla — with version extraction
            joomla_tag = self.soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Joomla', re.I)})
            if re.search(r'/components/com_|/modules/mod_|joomla', all_urls_text) or joomla_tag:
                tech_stack["cms"].append("Joomla")
                joomla_ver = None
                if joomla_tag:
                    joomla_ver = re.search(r'Joomla[! ]+(\d+\.\d+\.?\d*)', joomla_tag.get('content', ''), re.I)
                if not joomla_ver:
                    try:
                        r = requests.get(urljoin(self.base_url, '/administrator/manifests/files/joomla.xml'), headers=self.headers, timeout=5, verify=False)
                        if r.status_code == 200:
                            joomla_ver = re.search(r'<version>(\d+\.\d+\.?\d*)</version>', r.text)
                    except:
                        pass
                ver = joomla_ver.group(1) if joomla_ver else 'version unknown'
                tech_stack["cms_versions"] = tech_stack.get("cms_versions", {})
                tech_stack["cms_versions"]["Joomla"] = ver
                print(f"      Joomla {ver}")

            # Magento — with version extraction (strict patterns to avoid false positives)
            if re.search(r'magentocdn|/skin/frontend/|Mage\.Cookies|window\.Mage\b|Magento_|mage/utils|mage/storage', all_urls_text + self.html_content):
                tech_stack["cms"].append("Magento")
                magento_ver = None
                try:
                    r = requests.get(urljoin(self.base_url, '/magento_version'), headers=self.headers, timeout=5, verify=False)
                    if r.status_code == 200:
                        magento_ver = re.search(r'Magento/(\d+\.\d+\.?\d*)', r.text)
                except:
                    pass
                ver = magento_ver.group(1) if magento_ver else 'version unknown'
                tech_stack["cms_versions"] = tech_stack.get("cms_versions", {})
                tech_stack["cms_versions"]["Magento"] = ver
                print(f"      Magento {ver}")

            # Ghost
            if re.search(r'ghost-theme|ghost\.io|content/themes/.*ghost', all_urls_text):
                tech_stack["cms"].append("Ghost")
                print(f"      Ghost")

            # TYPO3
            if re.search(r'typo3|/typo3conf/|/typo3temp/', all_urls_text):
                tech_stack["cms"].append("TYPO3")
                print(f"      TYPO3")

            # PrestaShop
            if re.search(r'prestashop|/modules/.*prestashop', all_urls_text + (self.html_content or '').lower()):
                tech_stack["cms"].append("PrestaShop")
                print(f"      PrestaShop")

            # OpenCart
            if re.search(r'opencart|catalog/view/theme', all_urls_text + (self.html_content or '').lower()):
                tech_stack["cms"].append("OpenCart")
                print(f"      OpenCart")

            # Craft CMS
            if re.search(r'craft-cms|/cpresources/|craftcms', all_urls_text + (self.html_content or '').lower()):
                tech_stack["cms"].append("Craft CMS")
                print(f"      Craft CMS")

            # Umbraco
            if re.search(r'umbraco|/umbraco/', all_urls_text + (self.html_content or '').lower()):
                tech_stack["cms"].append("Umbraco")
                print(f"      Umbraco")

            # ✅ FIX 4: Add 4 missing CMSes
            # Squarespace
            if re.search(r'squarespace|static\.squarespace', all_urls_text):
                tech_stack["cms"].append("Squarespace")
                print(f"      Squarespace")

            # Sitecore
            if re.search(r'sitecore|/-/media/|/-/speak/', all_urls_text + (self.html_content or '').lower()):
                tech_stack["cms"].append("Sitecore")
                print(f"      Sitecore")

            # Webflow
            if re.search(r'webflow|assets\.website-files\.com', all_urls_text):
                tech_stack["cms"].append("Webflow")
                print(f"      Webflow")

            # HubSpot CMS
            if re.search(r'hubspot\.com.*content|hs-scripts|hscollectedforms', all_urls_text):
                tech_stack["cms"].append("HubSpot CMS")
                print(f"      HubSpot CMS")

            if not tech_stack["cms"]:
                print("      No CMS detected")
            
            # JavaScript Libraries with Versions
            print("\n   [JavaScript Libraries & Versions]")
            
            js_patterns = {
                "jQuery": [r'jquery[.-](\d+\.\d+\.?\d*)', r'jquery'],
                "Bootstrap": [r'bootstrap[.-](\d+\.\d+\.?\d*)', r'bootstrap'],
                "React": [r'react[.-](\d+\.\d+\.?\d*)', r'react'],
                "Angular": [r'angular[.-](\d+\.\d+\.?\d*)', r'angular'],
                "Vue.js": [r'vue[.-](\d+\.\d+\.?\d*)', r'vue'],
                "Lodash": [r'lodash[.-](\d+\.\d+\.?\d*)', r'lodash'],
                "Moment.js": [r'moment[.-](\d+\.\d+\.?\d*)', r'moment']
            }
            
            def is_valid_version(v):
                """Version must be X.Y or X.Y.Z — reject bare single digits like '3'"""
                return bool(re.fullmatch(r'\d+\.\d+\.?\d*', v))

            for lib_name, patterns in js_patterns.items():
                version_found = False

                for url in all_urls:
                    url_lower = url.lower()

                    version_match = re.search(patterns[0], url_lower)
                    if version_match and version_match.lastindex and version_match.lastindex >= 1:
                        version = version_match.group(1)
                        if not is_valid_version(version):
                            continue  # skip bad matches like single digit "3"

                        if lib_name not in tech_stack["javascript_libraries"]:
                            tech_stack["javascript_libraries"].append(lib_name)

                        tech_stack["javascript_versions"][lib_name] = version
                        print(f"      {lib_name} {version}")
                        version_found = True
                        break

                    elif re.search(patterns[1], url_lower):
                        if lib_name not in tech_stack["javascript_libraries"]:
                            tech_stack["javascript_libraries"].append(lib_name)

                        ver_match = re.search(r'[?&]ver=(\d+\.\d+\.?\d*)', url)
                        if ver_match and is_valid_version(ver_match.group(1)):
                            tech_stack["javascript_versions"][lib_name] = ver_match.group(1)
                            print(f"      {lib_name} {ver_match.group(1)}")
                            version_found = True
                            break
                
                if lib_name in tech_stack["javascript_libraries"] and lib_name not in tech_stack["javascript_versions"]:
                    # Fallback: scan HTML source for inline version comments
                    # e.g. "jQuery v3.6.0", "/*! Bootstrap v4.3.1", "React version: 16.8.0"
                    inline_patterns = {
                        "jQuery":    r'[Jj]Query\s+v?(\d+\.\d+\.?\d*)',
                        "Bootstrap": r'Bootstrap\s+v?(\d+\.\d+\.?\d*)',
                        "React":     r'[Rr]eact\s+v?(\d+\.\d+\.?\d*)',
                        "Angular":   r'[Aa]ngular\s+v?(\d+\.\d+\.?\d*)',
                        "Vue.js":    r'Vue\.js\s+v?(\d+\.\d+\.?\d*)',
                        "Lodash":    r'[Ll]odash\s+v?(\d+\.\d+\.?\d*)',
                        "Moment.js": r'[Mm]oment\.js\s+v?(\d+\.\d+\.?\d*)',
                    }
                    pattern = inline_patterns.get(lib_name)
                    if pattern:
                        m = re.search(pattern, self.html_content)
                        if m:
                            version = m.group(1)
                            tech_stack["javascript_versions"][lib_name] = version
                            print(f"      {lib_name} {version} (from inline comment)")
                        else:
                            print(f"      {lib_name} (version unknown)")
                    else:
                        print(f"      {lib_name} (version unknown)")

            if not tech_stack["javascript_libraries"]:
                print("      No JavaScript libraries detected")
            
            # Frameworks
            print("\n   [Frameworks]")
            frameworks = {
                "React": r'react[.-]|reactjs|data-react',
                "Angular": r'angular[.-]|@angular',
                "Vue.js": r'vue[.-]|vuejs',
                "Next.js": r'_next/',
                "Nuxt.js": r'_nuxt/',
                "Laravel": r'laravel',
                "Django": r'csrfmiddlewaretoken|django',
                "Ruby on Rails": r'data-turbo|rails-ujs|turbolinks',
                "ASP.NET": r'__viewstate|aspnetcore|asp\.net',
                "Symfony": r'sf-toolbar|symfony',
                "CodeIgniter": r'ci_session|codeigniter',
                "Spring": r'jsessionid|spring-framework',
                # ✅ FIX 4: Add 4 missing frameworks
                "Flask": r'flask|werkzeug',
                "PHP": r'\.php|x-powered-by.*php',
                "Svelte": r'svelte|_app/immutable',
                "Express.js": r'express|x-powered-by.*express'
            }
            
            tech_stack["framework_versions"] = {}
            # Version patterns in CDN URLs like react@16.8.0, @angular/core@12.0.0, vue@3.2.0
            fw_version_patterns = {
                "React":     r'react@(\d+\.\d+\.?\d*)',
                "Angular":   r'@angular/core@(\d+\.\d+\.?\d*)',
                "Vue.js":    r'vue@(\d+\.\d+\.?\d*)',
                "Svelte":    r'svelte@(\d+\.\d+\.?\d*)',
                "Express.js":r'express@(\d+\.\d+\.?\d*)',
            }

            for fw_name, pattern in frameworks.items():
                if re.search(pattern, all_urls_text):
                    if fw_name not in tech_stack["frameworks"]:
                        tech_stack["frameworks"].append(fw_name)
                    # Try to extract version
                    ver_pat = fw_version_patterns.get(fw_name)
                    if ver_pat:
                        vm = re.search(ver_pat, all_urls_text)
                        if vm and is_valid_version(vm.group(1)):
                            tech_stack["framework_versions"][fw_name] = vm.group(1)
                            print(f"      {fw_name} {vm.group(1)}")
                        else:
                            print(f"      {fw_name} (version unknown)")
                    else:
                        print(f"      {fw_name}")

            if not tech_stack["frameworks"]:
                print("      No frameworks detected")
            
            # Analytics
            print("\n   [Analytics]")
            analytics = {
                "Google Analytics": r'google-analytics|analytics\.js|gtag',
                "Google Tag Manager": r'googletagmanager|gtm\.js',
                "Facebook Pixel": r'facebook.*pixel|fbevents'
            }
            
            for analytics_name, pattern in analytics.items():
                if re.search(pattern, all_urls_text):
                    tech_stack["analytics"].append(analytics_name)
                    print(f"      {analytics_name}")
            
            if not tech_stack["analytics"]:
                print("      No analytics detected")
            
            # CDN
            print("\n   [CDN Services]")
            cdn_patterns = {
                "Cloudflare": r'cloudflare|cdnjs\.cloudflare',
                "AWS CloudFront": r'cloudfront\.net',
                "Akamai": r'akamai|akamaized',
                "Fastly": r'fastly\.net',
                "jsDelivr": r'jsdelivr\.net',
                "Google CDN": r'googleapis\.com|gstatic\.com'
            }
            
            for cdn_name, pattern in cdn_patterns.items():
                if re.search(pattern, all_urls_text):
                    tech_stack["cdn"].append(cdn_name)
                    print(f"      {cdn_name}")
            
            if not tech_stack["cdn"]:
                print("      No CDN detected")
            
            # Fonts
            if re.search(r'fonts\.googleapis|fonts\.gstatic', all_urls_text):
                tech_stack["fonts"].append("Google Fonts")
            if re.search(r'fontawesome|font-awesome', all_urls_text):
                tech_stack["fonts"].append("Font Awesome")
            
            tech_stack["all_detected"] = (
                tech_stack["cms"] + 
                tech_stack["frameworks"] + 
                tech_stack["javascript_libraries"] + 
                tech_stack["analytics"] + 
                tech_stack["cdn"]
            )
            
            self.results["2_web_server_stack"] = tech_stack
            
            print(f"\n   Total Technologies: {len(tech_stack['all_detected'])}")
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def erp_sap_detection(self):
        print("="*80)
        print("[3] ERP/SAP SYSTEM DETECTION")
        print("="*80)
        
        try:
            scripts = [s.get('src', '') for s in self.soup.find_all('script', src=True)]
            links = [l.get('href', '') for l in self.soup.find_all('link', href=True)]
            all_sources = ' '.join(scripts + links).lower()
            content_lower = (self.html_content or '').lower()
            
            # ENHANCED: Check both sources AND HTML content with context
            erp_patterns = {
                "SAP": {
                    "sources": [r'/sap/', r'/sapui5/', r'sap\.fiori', r'sap-ui-core'],
                    "content": [
                        r'sap\s+(partner|implementation|consultant|solution|service)',
                        r'(partner|solution)\s+with\s+sap',
                        r'sap\s+[a-z]+\s+implementation',
                        r'certified\s+sap',
                        r'sap\s+erp'
                    ]
                },
                "Oracle ERP": {
                    "sources": [r'/oa_html', r'/OA_MEDIA/', r'oracle-application'],
                    "content": [r'oracle\s+erp', r'oracle\s+(partner|implementation)']
                },
                "Microsoft Dynamics 365": {
                    "sources": [r'/dynamics/', r'dynamics365', r'dynamicscrm'],
                    "content": [r'dynamics\s+365', r'microsoft\s+dynamics']
                },
                "Salesforce": {
                    "sources": [r'salesforce\.com.*apex', r'force\.com', r'sfdc.*js'],
                    "content": [r'salesforce\s+(partner|implementation)']
                },
                "NetSuite": {
                    "sources": [r'system\.netsuite\.com', r'netsuite.*app'],
                    "content": [r'netsuite\s+(partner|implementation)']
                },
                "Workday": {
                    "sources": [r'workday\.com.*wd5', r'myworkday\.com'],
                    "content": [r'workday\s+(partner|implementation)']
                },
                "Odoo": {
                    "sources": [r'/web/static/', r'odoo.*web'],
                    "content": [r'odoo\s+erp']
                }
            }
            
            detected_erp = []
            detection_details = {}
            
            for erp_name, patterns in erp_patterns.items():
                detected = False
                method = ""
                
                # Check sources (scripts/links) first - STRONG indicator
                for pattern in patterns["sources"]:
                    if re.search(pattern, all_sources):
                        detected = True
                        method = "script/link source"
                        break
                
                # Check HTML content with context - WEAK indicator
                if not detected and "content" in patterns:
                    for pattern in patterns["content"]:
                        if re.search(pattern, content_lower):
                            detected = True
                            method = "content mention (partnership/service)"
                            break
                
                if detected:
                    detected_erp.append(erp_name)
                    detection_details[erp_name] = method
                    print(f"   {erp_name} - detected via {method}")

            # Fix #15: SAP version extraction from SAPUI5 URLs and meta tags
            erp_versions = {}
            if "SAP" in detected_erp:
                sap_ver = None
                # Pattern 1: /sapui5/resources/sap-ui-core.js?version=1.96.0
                sap_ver = sap_ver or re.search(r'sap-ui-core[^"\']*[?&]version=(\d+\.\d+\.?\d*)', all_sources, re.I)
                # Pattern 2: URL path like /sap/public/bc/ui5_ui5/1.96.0/
                sap_ver = sap_ver or re.search(r'/ui5_ui5/(\d+\.\d+\.?\d*)/', all_sources)
                # Pattern 3: data-sap-ui-version="1.96.0" in HTML
                sap_ver = sap_ver or re.search(r'data-sap-ui-version=["\'](\d+\.\d+\.?\d*)["\']', self.html_content, re.I)
                # Pattern 4: sap.ui.version = "1.96.0"
                sap_ver = sap_ver or re.search(r'sap\.ui\.version\s*[=:]\s*["\'](\d+\.\d+\.?\d*)["\']', self.html_content, re.I)
                if sap_ver:
                    ver = sap_ver.group(1)
                    erp_versions["SAP"] = ver
                    print(f"   SAP SAPUI5 version: {ver}")
                else:
                    print(f"   SAP version: not found in page source")

            self.results["3_erp_sap_detection"] = {
                "detected_systems": detected_erp,
                "detection_details": detection_details,
                "erp_versions": erp_versions,
                "using_erp": len(detected_erp) > 0
            }

            if not detected_erp:
                print("   No ERP/SAP systems detected")
            
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def third_party_software_inventory(self):
        print("="*80)
        print("[4] THIRD-PARTY SOFTWARE INVENTORY")
        print("="*80)
        
        try:
            scripts = [s.get('src', '') for s in self.soup.find_all('script', src=True)]
            links = [l.get('href', '') for l in self.soup.find_all('link', href=True)]
            all_text = ' '.join(scripts + links + [self.html_content]).lower()
            
            third_party = {
                "analytics": [],
                "payment": [],
                "chat": [],
                "cdn": [],
                "social": [],
                "video": [],
                "captcha": []
            }
            
            services = {
                "analytics": {
                    "Google Analytics": r'google-analytics|gtag|ga\.js',
                    "Google Tag Manager": r'googletagmanager|gtm',
                    "Facebook Pixel": r'facebook.*pixel|fbevents',
                    "Hotjar": r'hotjar',
                    "Mixpanel": r'mixpanel',
                    "HubSpot": r'hubspot|hs-scripts|hscollectedforms',
                    "Segment": r'segment\.com|segment\.io|analytics\.js.*segment',
                    "TikTok Pixel": r'analytics\.tiktok|tiktok.*pixel',
                    "Microsoft Clarity": r'clarity\.ms|microsoft.*clarity',
                    "Amplitude": r'amplitude\.com|amplitude\.js'
                },
                "payment": {
                    "Stripe": r'stripe\.com|js\.stripe',
                    "PayPal": r'paypal',
                    "Razorpay": r'razorpay',
                    "Square": r'squareup'
                },
                "chat": {
                    "Intercom": r'intercom\.io',
                    "Zendesk": r'zendesk|zdassets',
                    "Drift": r'drift\.com',
                    "LiveChat": r'livechat'
                },
                "cdn": {
                    "Cloudflare": r'cloudflare',
                    "AWS CloudFront": r'cloudfront',
                    "Akamai": r'akamai'
                },
                "social": {
                    "Facebook": r'facebook\.com|fbcdn',
                    "Twitter": r'twitter\.com|twimg',
                    "Instagram": r'instagram\.com',
                    "LinkedIn": r'linkedin\.com'
                },
                "video": {
                    "YouTube": r'youtube\.com|ytimg',
                    "Vimeo": r'vimeo'
                },
                "captcha": {
                    "reCAPTCHA": r'recaptcha',
                    "hCaptcha": r'hcaptcha'
                }
            }
            
            print()
            for category, service_dict in services.items():
                for service_name, pattern in service_dict.items():
                    if re.search(pattern, all_text):
                        third_party[category].append(service_name)
                        print(f"   {service_name} ({category})")

            self.results["4_third_party_software"] = third_party

            total = sum(len(v) for v in third_party.values())
            print(f"\n   Total Services: {total}")
            print()

            # ── Enhancement D: Subresource Integrity (SRI) check ──────────────
            print("   [Subresource Integrity (SRI) Check]")
            sri_missing = []
            for tag in self.soup.find_all(['script', 'link']):
                src = tag.get('src') or tag.get('href', '')
                if not src:
                    continue
                # Only check <script src> and <link rel="stylesheet"> — skip hreflang/canonical/alternate
                if tag.name == 'link':
                    rel = tag.get('rel', [])
                    if isinstance(rel, list):
                        rel = ' '.join(rel).lower()
                    if 'stylesheet' not in rel:
                        continue
                # Only external resources from other domains (CDN-hosted)
                if not src.startswith('http'):
                    continue
                from urllib.parse import urlparse
                src_host = urlparse(src).netloc.lower()
                own_host = self.domain.lower()
                if src_host == own_host or src_host.endswith('.' + own_host):
                    continue  # skip same-domain resources
                if not tag.get('integrity'):
                    sri_missing.append({'tag': tag.name, 'src': src[:80]})
                    print(f"      MISSING SRI: <{tag.name}> {src[:60]}")
            if not sri_missing:
                print("      All external tags have SRI integrity attributes")
            self.results["7_security_posture"]["sri_missing"] = sri_missing
            print()

            # ── Enhancement I: Client-side secrets scan ───────────────────────
            print("   [Client-Side Secrets Scan]")
            secrets_patterns = {
                "AWS Access Key":      r'AKIA[0-9A-Z]{16}',
                "AWS Secret Key":      r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',
                "Google API Key":      r'AIza[0-9A-Za-z\-_]{35}',
                "GitHub Token":        r'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}',
                "Stripe Secret Key":   r'sk_live_[0-9a-zA-Z]{24,}',
                "Stripe Publishable":  r'pk_live_[0-9a-zA-Z]{24,}',
                "Slack Token":         r'xox[baprs]-[0-9A-Za-z\-]{10,}',
                "Private Key":         r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
                "JWT Token":           r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
                "Generic API Token":   r'(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
                # Fix #20: 5 more secret patterns
                "Twilio API Key":      r'SK[0-9a-fA-F]{32}',
                "SendGrid API Key":    r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
                "Mailgun API Key":     r'key-[0-9a-zA-Z]{32}',
                "Square Access Token": r'sq0atp-[0-9A-Za-z\-_]{22}',
                "Firebase API Key":    r'AIza[0-9A-Za-z\-_]{35}(?:[^A-Za-z0-9]|$)'
            }
            found_secrets = []
            for secret_name, pattern in secrets_patterns.items():
                matches = re.findall(pattern, self.html_content)
                for match in matches[:2]:  # cap at 2 per type
                    snippet = match[:40] if isinstance(match, str) else str(match)[:40]
                    found_secrets.append({'type': secret_name, 'snippet': snippet + '...'})
                    print(f"      EXPOSED SECRET [{secret_name}]: {snippet}...")
            if not found_secrets:
                print("      No client-side secrets detected")
            self.results["4_third_party_software"]["exposed_secrets"] = found_secrets
            print()

            # ── Enhancement J + Fix #19: Contact info + social media harvesting ─
            print("   [Contact Info & Social Media Harvesting]")
            emails   = list(set(re.findall(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', self.html_content)))
            phones   = list(set(re.findall(r'tel:([\+0-9\-\(\)\s]{7,20})', self.html_content)))
            # Fix #19: social media
            twitter  = list(set(re.findall(r'twitter\.com/([A-Za-z0-9_]{1,15})(?:["\'/\s])', self.html_content)))
            linkedin = list(set(re.findall(r'linkedin\.com/company/([^/"\'\s?]+)', self.html_content)))
            github   = list(set(re.findall(r'github\.com/([^/"\'\s?]+)', self.html_content)))
            # Filter out generic/path tokens
            twitter  = [t for t in twitter  if t.lower() not in ('share','intent','home','hashtag','search')]
            linkedin = [l for l in linkedin if l.lower() not in ('in','pub','company','login')]
            github   = [g for g in github   if g.lower() not in ('login','join','features','topics','explore')]

            for e in emails[:5]:    print(f"      Email: {e}")
            for p in phones[:5]:    print(f"      Phone: {p.strip()}")
            for t in twitter[:3]:   print(f"      Twitter: @{t}")
            for l in linkedin[:3]:  print(f"      LinkedIn: {l}")
            for g in github[:3]:    print(f"      GitHub: {g}")
            if not any([emails, phones, twitter, linkedin, github]):
                print("      No contact/social info found in HTML")

            self.results["4_third_party_software"]["contact_info"] = {
                "emails":   emails[:10],
                "phones":   [p.strip() for p in phones[:10]],
                "twitter":  twitter[:5],
                "linkedin": linkedin[:5],
                "github":   github[:5]
            }
            print()

        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def code_repository_analysis(self):
        print("="*80)
        print("[5] CODE REPOSITORY ANALYSIS")
        print("="*80)

        try:
            repo_info = {
                "github_repos": [],
                "robots_disallow": [],
                "robots_sitemaps": []
            }

            # ── Enhancement F: robots.txt full parsing ────────────────────────
            print("\n   [robots.txt — Disallow & Sitemap Analysis]")
            try:
                r = requests.get(urljoin(self.base_url, '/robots.txt'),
                                 headers=self.headers, timeout=10, verify=False)
                if r.status_code == 200 and 'text' in r.headers.get('Content-Type', ''):
                    disallow_paths = re.findall(r'(?i)^Disallow:\s*(.+)$', r.text, re.MULTILINE)
                    disallow_paths = [p.strip() for p in disallow_paths if p.strip() and p.strip() != '/']
                    for path in disallow_paths[:20]:
                        repo_info["robots_disallow"].append(path)
                        flag = 'NOTABLE' if re.search(r'admin|api|internal|staging|backup|login|secret|private', path, re.I) else 'INFO'
                        print(f"      [{flag}] Disallow: {path}")
                    if not disallow_paths:
                        print("      robots.txt exists but no Disallow paths found")

                    # Fix #8: Parse Sitemap: directives
                    sitemap_urls = re.findall(r'(?i)^Sitemap:\s*(.+)$', r.text, re.MULTILINE)
                    sitemap_urls = [s.strip() for s in sitemap_urls if s.strip()]
                    for smap in sitemap_urls[:10]:
                        repo_info["robots_sitemaps"].append(smap)
                        print(f"      [SITEMAP] {smap}")
                    if sitemap_urls:
                        print(f"      Found {len(sitemap_urls)} sitemap URL(s) in robots.txt")
                else:
                    print("      robots.txt not accessible")
            except Exception:
                print("      robots.txt fetch failed")

            print("\n   [Searching GitHub]")
            company = self.domain.split('.')[0]

            try:
                api_url = f"https://api.github.com/search/repositories?q={company}+in:name&sort=stars&per_page=5"
                r = requests.get(api_url, timeout=30)

                if r.status_code == 200:
                    for item in r.json().get('items', []):
                        repo_info["github_repos"].append({
                            "name": item['full_name'],
                            "url": item['html_url'],
                            "stars": item['stargazers_count']
                        })
                        print(f"      {item['full_name']} ({item['stargazers_count']} stars)")
                if not repo_info["github_repos"]:
                    print("      No public GitHub repos found")
            except Exception:
                print("      GitHub search failed")

            self.results["5_code_repositories"] = repo_info

            print(f"\n   robots.txt Disallow paths: {len(repo_info['robots_disallow'])}")
            print(f"   GitHub Repos: {len(repo_info['github_repos'])}")
            print()

        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def outdated_software_detection(self):
        print("="*80)
        print("[6] OUTDATED SOFTWARE & JAVASCRIPT DETECTION")
        print("="*80)
        
        try:
            vuln_data = {
                "libraries": [],
                "vulnerable": [],
                "count": 0
            }
            
            stack       = self.results.get("2_web_server_stack", {})
            js_versions = stack.get("javascript_versions", {})
            # Also pull CMS versions into the same check pool
            # WordPress uses cms_version (string); Drupal/Joomla/Magento use cms_versions (dict)
            cms_ver_single = stack.get("cms_version")
            cms_ver_dict   = stack.get("cms_versions", {})
            cms_list       = stack.get("cms", [])
            if cms_ver_single and cms_list:
                cms_ver_dict[cms_list[0]] = cms_ver_single  # merge WordPress into dict
            
            vuln_rules = {
                "jQuery": {
                    "vulnerable": ["1.", "2.", "3.0.", "3.1.", "3.2.", "3.3.", "3.4.", "3.5.", "3.6."],
                    "current": "3.7.1",
                    "severity": "High"
                },
                "Bootstrap": {
                    "vulnerable": ["3.", "4.0.", "4.1.", "4.2.", "4.3.", "4.4.", "4.5.", "4.6."],
                    "current": "5.3.3",
                    "severity": "Medium"
                },
                "Angular": {
                    "vulnerable": ["1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.", "10.", "11.", "12.", "13.", "14.", "15.", "16.", "17."],
                    "current": "19.x",
                    "severity": "Critical"
                },
                "React": {
                    "vulnerable": ["15.", "16.0.", "16.1.", "16.2.", "16.3.", "16.4.", "16.5.", "16.6.", "16.7.", "16.8.", "16.9.", "16.10.", "16.11.", "16.12.", "16.13.", "16.14.", "17."],
                    "current": "18.3.1",
                    "severity": "Medium"
                },
                "Lodash": {
                    "vulnerable": ["3.", "4.0.", "4.1.", "4.2.", "4.3.", "4.4.", "4.5.", "4.6.", "4.7.", "4.8.", "4.9.", "4.10.", "4.11.", "4.12.", "4.13.", "4.14.", "4.15.", "4.16."],
                    "current": "4.17.21",
                    "severity": "High"
                },
                "Vue": {
                    "vulnerable": ["1.", "2.0.", "2.1.", "2.2.", "2.3.", "2.4.", "2.5.", "2.6."],
                    "current": "3.4.x",
                    "severity": "Medium"
                },
                "moment": {
                    "vulnerable": ["1.", "2.0.", "2.1.", "2.2.", "2.3.", "2.4.", "2.5.", "2.6.", "2.7.", "2.8.", "2.9.", "2.10.", "2.11.", "2.12.", "2.13.", "2.14.", "2.15.", "2.16.", "2.17.", "2.18.", "2.19.", "2.20.", "2.21.", "2.22.", "2.23.", "2.24.", "2.25.", "2.26.", "2.27.", "2.28."],
                    "current": "2.29.4",
                    "severity": "High"
                }
            }
            
            print()
            
            if js_versions:
                for lib_name, version in js_versions.items():
                    vuln_data["libraries"].append({
                        "library": lib_name,
                        "version": version
                    })
                    
                    if lib_name in vuln_rules:
                        rule = vuln_rules[lib_name]
                        is_vulnerable = any(version.startswith(v) for v in rule["vulnerable"])
                        
                        if is_vulnerable:
                            vuln_entry = {
                                "library": lib_name,
                                "current_version": version,
                                "recommended_version": rule["current"],
                                "severity": rule["severity"]
                            }
                            vuln_data["vulnerable"].append(vuln_entry)
                            vuln_data["count"] += 1
                            
                            print(f"   VULNERABLE: {lib_name} {version} -> {rule['current']} [{rule['severity']}]")
                        else:
                            print(f"   OK: {lib_name} {version}")
            else:
                print("   No JavaScript library versions detected for vulnerability analysis")
            
            self.results["6_outdated_software"] = vuln_data
            
            print(f"\n   Libraries Analyzed: {len(vuln_data['libraries'])}")
            print(f"   Vulnerable: {vuln_data['count']}")
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def security_posture_analysis(self):
        print("="*80)
        print("[7] SECURITY POSTURE ANALYSIS")
        print("="*80)

        try:
            security_data = {
                "security_headers": {},
                "header_issues": [],
                "cookie_security": [],
                "cors_policy": {},
                "admin_panels": [],
                "waf_detection": {},
                "js_sourcemaps": []
            }

            # ── Enhancement C: Header strength analysis ───────────────────────
            print("\n   [Security Headers — Strength Analysis]")

            hsts_val  = self.response.headers.get('Strict-Transport-Security', '')
            csp_val   = self.response.headers.get('Content-Security-Policy', '')
            xfo_val   = self.response.headers.get('X-Frame-Options', '')
            xcto_val  = self.response.headers.get('X-Content-Type-Options', '')
            rp_val    = self.response.headers.get('Referrer-Policy', '')
            pp_val    = self.response.headers.get('Permissions-Policy', '')
            xxss_val  = self.response.headers.get('X-XSS-Protection', '')
            coep_val  = self.response.headers.get('Cross-Origin-Embedder-Policy', '')
            coop_val  = self.response.headers.get('Cross-Origin-Opener-Policy', '')
            corp_val  = self.response.headers.get('Cross-Origin-Resource-Policy', '')

            def hdr_line(name, value):
                if value:
                    print(f"      {name}: {value[:60]}")
                else:
                    print(f"      {name}: MISSING")

            hdr_line("HSTS", hsts_val)
            if not hsts_val:
                security_data["header_issues"].append("HSTS missing — site can be downgraded to HTTP")
            else:
                max_age_m = re.search(r'max-age=(\d+)', hsts_val)
                if max_age_m and int(max_age_m.group(1)) < 31536000:
                    security_data["header_issues"].append(f"HSTS max-age {max_age_m.group(1)} < 31536000 (1 year minimum)")
                    print(f"         ^ WARNING: max-age is below 1-year minimum")
                if 'includeSubDomains' not in hsts_val:
                    security_data["header_issues"].append("HSTS missing includeSubDomains")
                    print(f"         ^ WARNING: includeSubDomains not set")
                if 'preload' not in hsts_val:
                    print(f"         ^ INFO: preload not set (optional but recommended)")

            hdr_line("CSP", csp_val)
            if not csp_val:
                security_data["header_issues"].append("CSP missing — XSS attacks not mitigated")
            else:
                if "'unsafe-inline'" in csp_val:
                    security_data["header_issues"].append("CSP contains 'unsafe-inline' — nullifies XSS protection")
                    print(f"         ^ WARNING: unsafe-inline found in CSP")
                if "'unsafe-eval'" in csp_val:
                    security_data["header_issues"].append("CSP contains 'unsafe-eval'")
                    print(f"         ^ WARNING: unsafe-eval found in CSP")
                if re.search(r"default-src\s+['\"]?\*['\"]?", csp_val):
                    security_data["header_issues"].append("CSP default-src * — too permissive")
                    print(f"         ^ WARNING: default-src * is too permissive")

            hdr_line("X-Frame-Options", xfo_val)
            if not xfo_val:
                security_data["header_issues"].append("X-Frame-Options missing — clickjacking risk")
            elif xfo_val.upper() not in ('DENY', 'SAMEORIGIN'):
                security_data["header_issues"].append(f"X-Frame-Options value '{xfo_val}' is non-standard")

            hdr_line("X-Content-Type-Options", xcto_val)
            if not xcto_val:
                security_data["header_issues"].append("X-Content-Type-Options missing — MIME sniffing risk")
            elif xcto_val.lower() != 'nosniff':
                security_data["header_issues"].append(f"X-Content-Type-Options should be 'nosniff', got '{xcto_val}'")

            hdr_line("Referrer-Policy", rp_val)
            # ✅ ENHANCEMENT C: Referrer-Policy strength check
            if not rp_val:
                security_data["header_issues"].append("Referrer-Policy missing — referrer leakage risk")
            else:
                # Strong policies
                strong_policies = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
                # Weak policies
                weak_policies = ['unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin']
                
                rp_lower = rp_val.lower()
                if any(weak in rp_lower for weak in weak_policies):
                    security_data["header_issues"].append(f"Referrer-Policy '{rp_val}' is weak — may leak sensitive URLs")
                    print(f"         ^ WARNING: Weak policy detected")
                elif not any(strong in rp_lower for strong in strong_policies):
                    security_data["header_issues"].append(f"Referrer-Policy '{rp_val}' is non-standard")
                    print(f"         ^ WARNING: Non-standard policy")

            hdr_line("Permissions-Policy", pp_val)

            # Fix #9: 4 additional modern security headers
            hdr_line("X-XSS-Protection", xxss_val)
            if xxss_val and xxss_val.strip() == '0':
                print(f"         ^ INFO: Set to 0 (disabled — correct for modern browsers with CSP)")
            elif not xxss_val:
                security_data["header_issues"].append("X-XSS-Protection missing (legacy but still checked by scanners)")

            hdr_line("Cross-Origin-Embedder-Policy", coep_val)
            if not coep_val:
                security_data["header_issues"].append("COEP missing — required for SharedArrayBuffer/Spectre protection")

            hdr_line("Cross-Origin-Opener-Policy", coop_val)
            if not coop_val:
                security_data["header_issues"].append("COOP missing — window isolation not enforced")

            hdr_line("Cross-Origin-Resource-Policy", corp_val)
            if not corp_val:
                security_data["header_issues"].append("CORP missing — cross-origin resource leakage possible")

            security_data["security_headers"] = {
                "Strict-Transport-Security":    {"present": bool(hsts_val),  "value": hsts_val  or "Not set"},
                "Content-Security-Policy":      {"present": bool(csp_val),   "value": csp_val   or "Not set"},
                "X-Frame-Options":              {"present": bool(xfo_val),   "value": xfo_val   or "Not set"},
                "X-Content-Type-Options":       {"present": bool(xcto_val),  "value": xcto_val  or "Not set"},
                "Referrer-Policy":              {"present": bool(rp_val),    "value": rp_val    or "Not set"},
                "Permissions-Policy":           {"present": bool(pp_val),    "value": pp_val    or "Not set"},
                "X-XSS-Protection":             {"present": bool(xxss_val),  "value": xxss_val  or "Not set"},
                "Cross-Origin-Embedder-Policy": {"present": bool(coep_val),  "value": coep_val  or "Not set"},
                "Cross-Origin-Opener-Policy":   {"present": bool(coop_val),  "value": coop_val  or "Not set"},
                "Cross-Origin-Resource-Policy": {"present": bool(corp_val),  "value": corp_val  or "Not set"},
            }

            if security_data["header_issues"]:
                print(f"\n      Header issues found: {len(security_data['header_issues'])}")
            else:
                print(f"\n      All security headers pass strength checks")

            print("\n   [Cookie Security]")

            # requests library stores multiple Set-Cookie as separate cookies object
            set_cookie_headers = []
            raw_cookies = self.response.raw.headers.getlist('Set-Cookie') if hasattr(self.response.raw.headers, 'getlist') else []
            if raw_cookies:
                set_cookie_headers = raw_cookies
            elif 'Set-Cookie' in self.response.headers:
                set_cookie_headers = [self.response.headers.get('Set-Cookie')]

            if set_cookie_headers:
                for cookie_header in set_cookie_headers:
                    # Extract SameSite value precisely
                    ss_match = re.search(r'SameSite=(\w+)', cookie_header, re.I)
                    samesite_val = ss_match.group(1).capitalize() if ss_match else None

                    cookie_analysis = {
                        "cookie":        cookie_header.split(';')[0].split('=')[0].strip(),
                        "httponly":      bool(re.search(r'\bHttpOnly\b', cookie_header, re.I)),
                        "secure":        bool(re.search(r'\bSecure\b', cookie_header, re.I)),
                        "samesite":      bool(samesite_val),
                        "samesite_value": samesite_val or "Not set"
                    }
                    security_data["cookie_security"].append(cookie_analysis)

                    flags = []
                    if cookie_analysis["httponly"]: flags.append("HttpOnly")
                    if cookie_analysis["secure"]:   flags.append("Secure")

                    # SameSite value assessment
                    if samesite_val == "Strict":
                        flags.append("SameSite=Strict ✅")
                        ss_status = "best"
                    elif samesite_val == "Lax":
                        flags.append("SameSite=Lax ⚠️")
                        ss_status = "weak"
                    elif samesite_val == "None":
                        if cookie_analysis["secure"]:
                            flags.append("SameSite=None (Secure) ⚠️")
                            ss_status = "risky"
                        else:
                            flags.append("SameSite=None (NO Secure!) 🚨")
                            ss_status = "vulnerable"
                    else:
                        ss_status = "missing"

                    overall = "Secure" if (cookie_analysis["httponly"] and cookie_analysis["secure"] and ss_status in ("best", "weak")) else "Warning"
                    print(f"      {cookie_analysis['cookie']}: {', '.join(flags) if flags else 'No security flags'} [{overall}]")
            else:
                print("      No cookies set in response")

            print("\n   [CORS Policy]")

            cors_headers = {
                "Access-Control-Allow-Origin": self.response.headers.get('Access-Control-Allow-Origin'),
                "Access-Control-Allow-Methods": self.response.headers.get('Access-Control-Allow-Methods'),
                "Access-Control-Allow-Headers": self.response.headers.get('Access-Control-Allow-Headers'),
                "Access-Control-Allow-Credentials": self.response.headers.get('Access-Control-Allow-Credentials')
            }

            security_data["cors_policy"] = cors_headers

            if cors_headers["Access-Control-Allow-Origin"]:
                origin = cors_headers["Access-Control-Allow-Origin"]
                if origin == "*":
                    print(f"      Open CORS: Allows all origins (*)")
                else:
                    print(f"      Restricted CORS: {origin}")
            else:
                print("      No CORS headers detected")

            print("\n   [Admin Panel Discovery]")

            admin_paths = [
                '/admin', '/administrator', '/admin.php', '/admin/',
                '/wp-admin', '/wp-login.php',
                '/phpmyadmin', '/pma',
                '/cpanel', '/plesk',
                '/adminer.php', '/adminer',
                '/manager/html',
                '/login', '/signin', '/auth/login',
                # Fix #18: 10 more common paths
                '/dashboard', '/console', '/backend',
                '/control-panel', '/admin-console',
                '/admin_area', '/admin-login',
                '/user/login', '/adminpanel',
                '/administrator/index.php'
            ]

            for path in admin_paths:
                try:
                    r = requests.head(urljoin(self.base_url, path),
                                     headers=self.headers, timeout=8, verify=False, allow_redirects=False)

                    # Only report 200, 401, 403 - ignore redirects
                    if r.status_code in [200, 401, 403]:
                        security_data["admin_panels"].append({
                            "path": path,
                            "status": r.status_code
                        })

                        if r.status_code == 200:
                            print(f"      EXPOSED: {path} [{r.status_code}]")
                        elif r.status_code in [401, 403]:
                            print(f"      Protected: {path} [{r.status_code}]")
                except:
                    pass

            if not security_data["admin_panels"]:
                print("      No exposed admin panels found")

            # ── Fix 2: WAF Detection ──────────────────────────────────────────
            print("\n   [WAF Detection]")
            waf_detected = []
            body_lower = self.html_content.lower() if self.html_content else ''
            resp_headers_lower = {k.lower(): v.lower() for k, v in self.response.headers.items()}

            waf_signatures = [
                # (WAF name, header key, header value pattern) — None key = body check
                ("Cloudflare",          "cf-ray",               None),
                ("Cloudflare",          "server",               r'cloudflare'),
                ("Cloudflare",          "cf-cache-status",      None),
                ("Cloudflare",          "cf-request-id",        None),
                ("Cloudflare",          "report-to",            r'cloudflare'),
                ("AWS WAF",             "x-amzn-requestid",  None),
                ("AWS WAF",             "x-amzn-trace-id",   None),
                ("Akamai",              "x-akamai-transformed", None),
                ("Akamai",              "server",            r'akamaighost'),
                ("Imperva / Incapsula", "x-iinfo",           None),
                ("Imperva / Incapsula", "x-cdn",             r'incapsula'),
                ("F5 BIG-IP",           "x-wa-info",         None),
                ("F5 BIG-IP",           "server",            r'big-ip'),
                ("Barracuda",           "x-barracuda-connect", None),
                ("Sucuri",              "x-sucuri-id",       None),
                ("Sucuri",              "server",            r'sucuri'),
                ("ModSecurity",         "server",            r'mod_security'),
                ("Fastly",              "x-fastly-request-id", None),
            ]

            for waf_name, hdr_key, hdr_pattern in waf_signatures:
                if hdr_key in resp_headers_lower:
                    val = resp_headers_lower[hdr_key]
                    if hdr_pattern is None or re.search(hdr_pattern, val):
                        if waf_name not in waf_detected:
                            waf_detected.append(waf_name)
                            print(f"      DETECTED: {waf_name} (header: {hdr_key})")

            # Body-based WAF fingerprints
            waf_body_sigs = [
                ("Cloudflare",    r'cloudflare.*ray id|cf-browser-verification'),
                ("AWS WAF",       r'aws.*waf|request blocked.*aws'),
                ("Incapsula",     r'incapsula incident id'),
                ("Sucuri",        r'sucuri website firewall'),
                ("Barracuda",     r'barracuda.*web.*application.*firewall'),
                ("ModSecurity",   r'mod_security|this error was generated by mod_security'),
                ("Wordfence",     r'wordfence.*blocked|generated by wordfence'),
                ("SiteLock",      r'sitelock'),
                ("DenyAll",       r'denyall'),
                ("Wallarm",       r'wallarm'),
            ]
            for waf_name, pattern in waf_body_sigs:
                if re.search(pattern, body_lower) and waf_name not in waf_detected:
                    waf_detected.append(waf_name)
                    print(f"      DETECTED: {waf_name} (body signature)")

            if not waf_detected:
                print("      No WAF signatures detected")
            security_data["waf_detection"] = {
                "detected": bool(waf_detected),
                "waf_names": waf_detected,
                "waf_name": ', '.join(waf_detected) if waf_detected else None
            }

            # ── Enhancement E: JS Source Map Exposure ─────────────────────────
            print("\n   [JS Source Map Exposure]")
            js_urls = [s.get('src', '') for s in self.soup.find_all('script', src=True) if s.get('src', '').endswith('.js')]
            for js_url in js_urls[:10]:
                map_url = js_url if js_url.startswith('http') else urljoin(self.base_url, js_url)
                map_url = map_url + '.map'
                try:
                    r = requests.head(map_url, headers=self.headers, timeout=8, verify=False, allow_redirects=True)
                    if r.status_code == 200:
                        security_data["js_sourcemaps"].append(map_url)
                        print(f"      EXPOSED: {map_url[:70]}")
                except Exception:
                    pass
            if not security_data["js_sourcemaps"]:
                print("      No exposed .js.map files found")

            # ✅ ENHANCEMENT 2: Open Redirect Check
            print("\n   [Open Redirect Vulnerability Test]")
            security_data["open_redirect"] = []
            redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'redir', 'target', 'dest', 'destination', 'continue']
            test_payload = 'https://evil.com'
            
            for param in redirect_params[:5]:  # Test top 5 params
                test_url = f"{self.base_url}?{param}={test_payload}"
                try:
                    r = requests.get(test_url, headers=self.headers, timeout=5, verify=False, allow_redirects=False)
                    if r.status_code in [301, 302, 303, 307, 308]:
                        location = r.headers.get('Location', '')
                        # Only flag if redirect goes to external domain (not same domain)
                        from urllib.parse import urlparse
                        loc_host = urlparse(location).netloc.lower()
                        own_host = urlparse(self.base_url).netloc.lower().lstrip('www.')
                        is_external = loc_host and not loc_host.lstrip('www.').endswith(own_host)
                        if test_payload in location and is_external:
                            security_data["open_redirect"].append({
                                'param': param,
                                'test_url': test_url,
                                'vulnerable': True,
                                'redirect_to': location
                            })
                            print(f"      🚨 VULNERABLE: ?{param}= redirects to {location[:50]}")
                except:
                    pass
            
            if not security_data["open_redirect"]:
                print("      ✅ No open redirect vulnerabilities found")

            # ✅ ENHANCEMENT 3: Clickjacking Test
            print("\n   [Clickjacking Protection Test]")
            security_data["clickjacking"] = {
                'x_frame_options': xfo_val,
                'csp_frame_ancestors': None,
                'protected': False,
                'method': None
            }
            
            # Check X-Frame-Options
            if xfo_val and xfo_val.upper() in ('DENY', 'SAMEORIGIN'):
                security_data["clickjacking"]['protected'] = True
                security_data["clickjacking"]['method'] = 'X-Frame-Options'
                print(f"      ✅ Protected via X-Frame-Options: {xfo_val}")
            
            # Check CSP frame-ancestors
            if csp_val and 'frame-ancestors' in csp_val:
                frame_ancestors = re.search(r"frame-ancestors\s+([^;]+)", csp_val)
                if frame_ancestors:
                    policy = frame_ancestors.group(1).strip()
                    security_data["clickjacking"]['csp_frame_ancestors'] = policy
                    if policy in ["'none'", "'self'"]:
                        security_data["clickjacking"]['protected'] = True
                        security_data["clickjacking"]['method'] = 'CSP frame-ancestors'
                        print(f"      ✅ Protected via CSP frame-ancestors: {policy}")
            
            if not security_data["clickjacking"]['protected']:
                print(f"      🚨 VULNERABLE: No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)")

            # ✅ ENHANCEMENT 4: SSL/TLS Certificate Info
            print("\n   [SSL/TLS Certificate Information]")
            security_data["ssl_certificate"] = {}
            
            if self.base_url.startswith('https://'):
                try:
                    import ssl
                    import socket
                    from datetime import datetime
                    
                    # Use CERT_OPTIONAL so getpeercert() returns structured data
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_OPTIONAL
                    context.load_default_certs()

                    with socket.create_connection((self.domain, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            cert = ssock.getpeercert() or {}
                            
                            # Extract certificate details
                            subject = dict(x[0] for x in cert.get('subject', []))
                            issuer = dict(x[0] for x in cert.get('issuer', []))
                            
                            # Parse dates
                            not_before = cert.get('notBefore', '')
                            not_after = cert.get('notAfter', '')
                            
                            # Calculate days until expiry
                            if not_after:
                                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_left = (expiry_date - datetime.now()).days
                            else:
                                days_left = None
                            
                            # Extract SANs (Subject Alternative Names)
                            san_list = []
                            for san_type, san_value in cert.get('subjectAltName', []):
                                if san_type == 'DNS':
                                    san_list.append(san_value)
                            
                            common_name  = subject.get('commonName', '')
                            issuer_cn    = issuer.get('commonName', 'N/A')
                            issuer_org   = issuer.get('organizationName', 'N/A')

                            # Fix #11a: Self-signed check — issuer == subject
                            # Only flag if we actually have cert data (non-empty subject/issuer)
                            is_self_signed = bool(subject) and bool(issuer) and (subject == issuer)

                            # Fix #11b: Expired check
                            is_expired = (days_left is not None and days_left < 0)

                            # Fix #11c: Domain match check — CN or SANs must cover the domain
                            def domain_matches(pattern, domain):
                                if pattern.startswith('*.'):
                                    return domain.endswith(pattern[1:])
                                return pattern.lower() == domain.lower()

                            covered = any(domain_matches(s, self.domain) for s in san_list + [common_name])
                            domain_mismatch = not covered

                            cert_issues = []
                            if is_self_signed:   cert_issues.append("Self-signed certificate")
                            if is_expired:       cert_issues.append(f"Certificate EXPIRED {abs(days_left)} days ago")
                            if domain_mismatch:  cert_issues.append(f"Domain mismatch — cert CN={common_name} doesn't cover {self.domain}")

                            security_data["ssl_certificate"] = {
                                'common_name':       common_name or 'N/A',
                                'issuer':            issuer_cn,
                                'issuer_org':        issuer_org,
                                'not_before':        not_before,
                                'not_after':         not_after,
                                'days_until_expiry': days_left,
                                'subject_alt_names': san_list,
                                'san_count':         len(san_list),
                                'is_self_signed':    is_self_signed,
                                'is_expired':        is_expired,
                                'domain_mismatch':   domain_mismatch,
                                'cert_issues':       cert_issues
                            }

                            print(f"      Common Name:  {common_name or 'N/A'}")
                            print(f"      Issuer:       {issuer_cn} ({issuer_org})")
                            print(f"      Valid Until:  {not_after}")

                            if days_left is not None:
                                if days_left < 0:
                                    print(f"      EXPIRED {abs(days_left)} days ago!")
                                elif days_left < 14:
                                    print(f"      CRITICAL: Expiring in {days_left} days!")
                                elif days_left < 30:
                                    print(f"      WARNING: Expiring in {days_left} days")
                                else:
                                    print(f"      Valid for {days_left} more days")

                            for issue in cert_issues:
                                print(f"      ISSUE: {issue}")

                            if san_list:
                                print(f"      SANs: {len(san_list)} domain(s)")
                                for san in san_list[:5]:
                                    print(f"         • {san}")
                                if len(san_list) > 5:
                                    print(f"         ... and {len(san_list) - 5} more")
                            
                except Exception as e:
                    print(f"      ⚠️ Could not retrieve certificate: {str(e)[:50]}")
            else:
                print("      ⚠️ Site uses HTTP (no SSL/TLS)")

            self.results["7_security_posture"] = security_data

            print()

        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def api_endpoint_discovery(self):
        print("="*80)
        print("[8] API ENDPOINT DISCOVERY")
        print("="*80)
        
        try:
            api_data = {
                "api_endpoints": [],
                "api_documentation": [],
                "graphql_endpoints": []
            }
            
            print("\n   [Checking Common API Paths]")
            
            api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/rest', '/rest/v1',
                '/graphql', '/gql',
                '/swagger', '/swagger-ui', '/swagger.json', '/swagger/index.html',
                '/api-docs', '/api/docs', '/docs',
                '/openapi.json', '/openapi.yaml',
                '/.well-known/openapi'
            ]
            
            for path in api_paths:
                try:
                    r = requests.head(urljoin(self.base_url, path),
                                     headers=self.headers, timeout=8, verify=False, allow_redirects=False)
                    
                    # Only report 200 status - ignore redirects
                    if r.status_code == 200:
                        endpoint_info = {
                            "path": path,
                            "status": r.status_code,
                            "content_type": r.headers.get('Content-Type', 'unknown')
                        }
                        
                        if 'graphql' in path or 'gql' in path:
                            api_data["graphql_endpoints"].append(endpoint_info)
                            print(f"      GraphQL: {path} [{r.status_code}]")
                        elif any(doc in path for doc in ['swagger', 'openapi', 'docs']):
                            api_data["api_documentation"].append(endpoint_info)
                            print(f"      API Docs: {path} [{r.status_code}]")
                        else:
                            api_data["api_endpoints"].append(endpoint_info)
                            print(f"      API Endpoint: {path} [{r.status_code}]")
                except:
                    pass
            
            print("\n   [Searching HTML for API References]")
            
            api_patterns = [
                r'(https?://[^"\']+/api[^"\']*)',
                r'(https?://[^"\']+/graphql[^"\']*)',
                r'(https?://[^"\']+/swagger[^"\']*)'
            ]
            
            found_in_html = []
            for pattern in api_patterns:
                matches = re.findall(pattern, self.html_content)
                for match in matches[:3]:
                    if match not in found_in_html:
                        found_in_html.append(match)
                        print(f"      Found in HTML: {match[:60]}")
            
            if found_in_html:
                api_data["api_links_in_html"] = found_in_html
            
            # --- Fix #12: Dynamic API version enumeration ---
            # When a versioned API base (e.g. /api/v1, /rest/v1) is confirmed active,
            # probe additional version numbers automatically.
            print("\n   [API Version Enumeration]")
            version_base_pattern = re.compile(r'^(/(?:api|rest|v))/v(\d+)$')
            probed_versions = {}
            for ep in list(api_data["api_endpoints"]):
                m = version_base_pattern.match(ep["path"])
                if not m:
                    continue
                base_prefix = m.group(1)   # e.g. /api or /rest
                if base_prefix in probed_versions:
                    continue   # already enumerated this base
                probed_versions[base_prefix] = []
                # probe v1 through v6 (skip already-found one)
                for v in range(1, 7):
                    probe_path = f"{base_prefix}/v{v}"
                    if probe_path == ep["path"]:
                        probed_versions[base_prefix].append(v)
                        continue
                    try:
                        r2 = requests.head(urljoin(self.base_url, probe_path),
                                           headers=self.headers, timeout=8, verify=False,
                                           allow_redirects=False)
                        if r2.status_code == 200:
                            probed_versions[base_prefix].append(v)
                            extra_ep = {
                                "path": probe_path,
                                "status": 200,
                                "content_type": r2.headers.get('Content-Type', 'unknown')
                            }
                            if extra_ep not in api_data["api_endpoints"]:
                                api_data["api_endpoints"].append(extra_ep)
                            print(f"      Version found: {probe_path} [200]")
                    except:
                        pass
            if probed_versions:
                api_data["active_api_versions"] = {
                    base: [f"v{v}" for v in sorted(vers)]
                    for base, vers in probed_versions.items()
                }
            else:
                print("      No versioned API bases to enumerate")
            # --- end Fix #12 ---

            total_apis = len(api_data["api_endpoints"]) + len(api_data["graphql_endpoints"]) + len(api_data["api_documentation"])

            if total_apis == 0 and not found_in_html:
                print("\n      No API endpoints discovered")

            self.results["8_api_discovery"] = api_data
            
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    def database_detection(self):
        print("="*80)
        print("[9] DATABASE & BACKEND DETECTION")
        print("="*80)
        
        try:
            db_data = {
                "database_type": [],
                "database_errors": [],
                "exposed_ports": [],
                "backend_hints": []
            }

            content_lower = (self.html_content or '').lower()
            
            print("\n   [Database Error Detection]")
            
            db_error_patterns = {
                "MySQL": [
                    r"mysql error", r"mysqli", r"you have an error in your sql syntax",
                    r"warning: mysql", r"mysql_fetch", r"mysql_connect"
                ],
                "PostgreSQL": [
                    r"postgresql", r"postgres", r"pg_query", r"pg_exec",
                    r"psql error", r"pgsql"
                ],
                "MongoDB": [
                    r"mongodb", r"mongo error", r"mongoclient"
                ],
                "Oracle": [
                    r"ora-\d+", r"oracle error", r"oci_execute"
                ],
                "MSSQL": [
                    r"microsoft sql", r"mssql", r"sql server",
                    r"odbc sql server driver"
                ],
                "SQLite": [
                    r"sqlite", r"sqlite3"
                ]
            }
            
            for db_name, patterns in db_error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower):
                        if db_name not in db_data["database_type"]:
                            db_data["database_type"].append(db_name)
                            print(f"      {db_name} detected from error/reference")
                        break
            
            print("\n   [Port Detection]")
            
            port_patterns = {
                "MySQL": r':3306',
                "PostgreSQL": r':5432',
                "MongoDB": r':27017',
                "Redis": r':6379',
                "Memcached": r':11211'
            }
            
            for db_name, port_pattern in port_patterns.items():
                if re.search(port_pattern, content_lower):
                    db_data["exposed_ports"].append({
                        "database": db_name,
                        "port": port_pattern.replace(':', '')
                    })
                    print(f"      {db_name} port {port_pattern} found in content!")
            
            print("\n   [Backend Technology Hints]")
            
            backend_patterns = {
                "Redis": r'redis',
                "Memcached": r'memcache',
                "Elasticsearch": r'elasticsearch',
                "RabbitMQ": r'rabbitmq',
                "Apache Kafka": r'kafka'
            }
            
            for tech_name, pattern in backend_patterns.items():
                if re.search(pattern, content_lower):
                    db_data["backend_hints"].append(tech_name)
                    print(f"      {tech_name} reference found")
            
            if not db_data["database_type"] and not db_data["backend_hints"] and not db_data["exposed_ports"]:
                print("\n      No database/backend information detected")

            # Fix #13: Connection string extraction
            print("\n   [Connection String Scan]")
            conn_patterns = {
                "MySQL":      r'mysql://([^:]+):([^@]+)@([^:/]+)[:/]',
                "PostgreSQL": r'postgres(?:ql)?://([^:]+):([^@]+)@([^:/]+)[:/]',
                "MongoDB":    r'mongodb(?:\+srv)?://([^:]+):([^@]+)@([^:/]+)[:/]',
                "MSSQL":      r'(?i)(?:server|data source)\s*=\s*([^;]+);.*?(?:user id|uid)\s*=\s*([^;]+);.*?(?:password|pwd)\s*=\s*([^;]+)',
                "Redis":      r'redis://(?:([^:]+):([^@]+)@)?([^:/]+)[:/]',
                "Generic JDBC": r'jdbc:(\w+)://([^:/]+)[:/](\d+)?/?(\w+)?[?;]?(?:user|username)=([^;&]+)',
            }
            found_conn_strings = []
            for db_type, pattern in conn_patterns.items():
                matches = re.findall(pattern, self.html_content + ' ' + ' '.join(
                    [s.get('src', '') for s in self.soup.find_all('script', src=False)]
                ))
                for match in matches[:2]:
                    parts = [str(p) for p in match if p]
                    snippet = f"{db_type}://{'/'.join(parts[:3])}"
                    found_conn_strings.append({'type': db_type, 'snippet': snippet})
                    print(f"      EXPOSED: {db_type} connection string — {snippet}")
            if not found_conn_strings:
                print("      No connection strings found in page source")
            db_data["connection_strings"] = found_conn_strings

            self.results["9_database_detection"] = db_data
            
            print()
            
        except Exception as e:
            print(f"   Error: {str(e)}\n")

    
    # =================================================================
    # ✅ NEW 23 API INTEGRATIONS (Phase 3 - Application Landscape)
    # ADD THESE METHODS AFTER database_detection
    # =================================================================
    
    def query_threat_intel_apis(self, ip_addresses: list) -> dict:
        """Query threat intelligence APIs (AbuseIPDB, AlienVault, GreyNoise, MetaDefender)"""
        if not API_CONFIG_AVAILABLE or not ip_addresses:
            return {}
        
        print("="*80)
        print("[10] THREAT INTELLIGENCE ANALYSIS (NEW APIs)")
        print("="*80)
        print()
        
        threat_results = {}
        
        try:
            threat_apis = APPLICATION_LANDSCAPE_APIS['threat_intel']
            
            for ip in ip_addresses[:2]:  # Limit to first 2 IPs
                print(f"   Checking IP: {ip}")
                
                # 1. AbuseIPDB
                if threat_apis['abuseipdb']['enabled']:
                    try:
                        url = f"{threat_apis['abuseipdb']['endpoint']}"
                        headers = {
                            'Key': threat_apis['abuseipdb']['api_key'],
                            'Accept': 'application/json'
                        }
                        params = {'ipAddress': ip, 'maxAgeInDays': 90}
                        
                        response = requests.get(url, headers=headers, params=params, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                            threat_results[f"{ip}_abuseipdb"] = data
                            print(f"      ✅ AbuseIPDB: Abuse Score = {abuse_score}%")
                    except Exception as e:
                        print(f"      ⚠️ AbuseIPDB error: {e}")
                
                # 2. AlienVault OTX
                if threat_apis['alienvault']['enabled']:
                    try:
                        url = f"{threat_apis['alienvault']['endpoint']}{ip}/general"
                        headers = {'X-OTX-API-KEY': threat_apis['alienvault']['api_key']}
                        
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            pulse_count = data.get('pulse_info', {}).get('count', 0)
                            threat_results[f"{ip}_alienvault"] = data
                            print(f"      ✅ AlienVault: {pulse_count} threat pulses")
                    except Exception as e:
                        print(f"      ⚠️ AlienVault error: {e}")
                
                # 3. GreyNoise
                if threat_apis['greynoise']['enabled']:
                    try:
                        url = f"{threat_apis['greynoise']['endpoint']}{ip}"
                        headers = {'key': threat_apis['greynoise']['api_key']}
                        
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            classification = data.get('classification', 'unknown')
                            threat_results[f"{ip}_greynoise"] = data
                            print(f"      ✅ GreyNoise: Classification = {classification}")
                    except Exception as e:
                        print(f"      ⚠️ GreyNoise error: {e}")
                
                # 4. MetaDefender
                if threat_apis['metadefender']['enabled']:
                    try:
                        url = f"{threat_apis['metadefender']['endpoint']}{ip}"
                        headers = {'apikey': threat_apis['metadefender']['api_key']}
                        
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            detections = data.get('detections', 0)
                            threat_results[f"{ip}_metadefender"] = data
                            print(f"      ✅ MetaDefender: {detections} detections")
                    except Exception as e:
                        print(f"      ⚠️ MetaDefender error: {e}")
                
                print()
        
        except Exception as e:
            print(f"   Error: {e}\n")
        
        return threat_results
    
    def query_leak_detection_apis(self, domain: str, ip_addresses: list) -> dict:
        """Query data leak detection APIs (LeakIX, Citadel)"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[11] DATA LEAK DETECTION (NEW APIs)")
        print("="*80)
        print()
        
        leak_results = {}
        
        try:
            leak_apis = APPLICATION_LANDSCAPE_APIS['leaks']
            
            # LeakIX
            if leak_apis['leakix']['enabled'] and ip_addresses:
                for ip in ip_addresses[:2]:
                    try:
                        url = f"{leak_apis['leakix']['endpoint']}{ip}"
                        headers = {'api-key': leak_apis['leakix']['api_key']}
                        
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            leak_results[f"{ip}_leakix"] = data
                            print(f"   ✅ LeakIX: {ip} - Leaks found")
                    except Exception as e:
                        print(f"   ⚠️ LeakIX error for {ip}: {e}")
            
            # ✅ ADD CITADEL
            if leak_apis['citadel']['enabled']:
                try:
                    url = leak_apis['citadel']['endpoint']
                    payload = {
                        'key': leak_apis['citadel']['api_key'],
                        'type': 'domain',
                        'query': domain
                    }
                    
                    response = requests.post(url, data=payload, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        breaches = data.get('message', []) if isinstance(data.get('message'), list) else []
                        leak_results[f"{domain}_citadel"] = data
                        print(f"   ✅ Citadel: {len(breaches)} breaches found for {domain}")
                except Exception as e:
                    print(f"   ⚠️ Citadel error: {e}")
            
            print()
        
        except Exception as e:
            print(f"   Error: {e}\n")
        
        return leak_results

    
    def query_grayhatwarfare(self, domain: str) -> dict:
        """GrayHatWarfare - S3 bucket exposure detection"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[12] S3 BUCKET EXPOSURE CHECK (NEW API)")
        print("="*80)
        print()
        
        try:
            config = APPLICATION_LANDSCAPE_APIS['exposure']
            if not config['enabled']:
                print("   GrayHatWarfare API disabled\n")
                return {}
            
            url = f"{config['endpoint']}/{domain}"
            params = {'access_token': config['api_key']}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                files_count = data.get('files', 0)
                print(f"   ✅ GrayHatWarfare: Found {files_count} exposed files")
                print()
                return data
            else:
                print(f"   ⚠️ GrayHatWarfare: HTTP {response.status_code}\n")
        
        except Exception as e:
            print(f"   ⚠️ GrayHatWarfare error: {e}\n")
        
        return {}
    
    def query_whatcms(self, domain: str) -> dict:
        """Query WhatCMS API for CMS and technology detection"""
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[13] WHATCMS - CMS & TECHNOLOGY DETECTION (NEW API)")
        print("="*80)
        print()
        
        try:
            # ✅ Get config from APPLICATION_LANDSCAPE_APIS (like other APIs)
            whatcms_config = APPLICATION_LANDSCAPE_APIS.get('whatcms', {})
            
            if not whatcms_config.get('enabled', False):
                print("   WhatCMS API disabled\n")
                return {}
            
            api_key = whatcms_config.get('api_key', '')
            endpoint = whatcms_config.get('endpoint', '')
            
            # Ensure proper URL format
            if not domain.startswith('http'):
                url = f"https://www.{domain}"
            else:
                url = domain
            
            # URL encoding for API call
            from urllib.parse import quote
            encoded_url = quote(url, safe='')
            
            # Build API URL
            api_url = f"{endpoint}?key={api_key}&url={encoded_url}"
            
            print(f"   Querying WhatCMS for: {domain}")
            
            response = requests.get(api_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check API response code
                result_code = data.get('result', {}).get('code')
                
                if result_code == 200:
                    results = data.get('results', [])
                    meta = data.get('meta', {})
                    
                    print(f"   ✅ WhatCMS: Detected {len(results)} technologies")
                    
                    # Print detected technologies
                    for tech in results:
                        categories = ', '.join(tech.get('categories', []))
                        print(f"      - {tech.get('name')} ({categories})")
                    
                    # Return structured data
                    return {
                        'status': 'success',
                        'technologies': results,
                        'social_media': meta.get('social', []),
                        'detected_count': len(results),
                        'raw_response': data
                    }
                
                elif result_code == 201:
                    print("   ℹ️ WhatCMS: No CMS detected")
                    return {
                        'status': 'no_cms_detected',
                        'technologies': [],
                        'message': 'No CMS detected'
                    }
                
                elif result_code == 111:
                    print(f"   ❌ WhatCMS: Invalid URL")
                    return {
                        'status': 'error',
                        'error': 'Invalid URL format'
                    }
                
                else:
                    print(f"   ⚠️ WhatCMS: API returned code {result_code}")
                    return {
                        'status': 'error',
                        'error': data.get('result', {}).get('msg', 'Unknown error')
                    }
            
            else:
                print(f"   ⚠️ WhatCMS: HTTP {response.status_code}")
                return {
                    'status': 'error',
                    'error': f'HTTP {response.status_code}'
                }
            
            print()
        
        except Exception as e:
            print(f"   ⚠️ WhatCMS error: {e}\n")
            return {
                'status': 'error',
                'error': str(e)
            }
        
    def query_pastebin_leaks(self, domain: str) -> dict:
        """
        PasteBin Search via Google Custom Search API
        Based on SpiderFoot sfp_pastebin module - Domain search only
        """
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[PASTEBIN] DATA LEAK DETECTION")
        print("="*80)
        print()
        
        try:
            pastebin_config = APPLICATION_LANDSCAPE_APIS.get('leaks', {}).get('pastebin_search', {})
            
            if not pastebin_config.get('enabled', False):
                print("  PasteBin Search API disabled\n")
                return {'status': 'disabled'}
            
            api_key = pastebin_config.get('api_key', '')
            cse_id = pastebin_config.get('cse_id', '')
            endpoint = pastebin_config.get('endpoint', '')
            
            # Construct search query (SpiderFoot style)
            search_query = f'site:pastebin.com "{domain}"'
            
            params = {
                'key': api_key,
                'cx': cse_id,
                'q': search_query,
                'num': 10  # Max results per request
            }
            
            print(f"  Searching PasteBin for: {domain}")
            print(f"  Query: {search_query}\n")
            
            response = requests.get(endpoint, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'items' in data:
                    total_found = len(data['items'])
                    print(f"  [+] Google returned {total_found} potential results\n")
                    
                    verified_leaks = []
                    found_urls = set()
                    
                    for idx, item in enumerate(data['items'], 1):
                        url = item.get('link', '')
                        title = item.get('title', 'N/A')
                        snippet = item.get('snippet', 'N/A')
                        
                        print(f"  [{idx}/{total_found}] {title}")
                        print(f"       URL: {url}")
                        
                        # URL validation (SpiderFoot style)
                        if not (url.startswith('https://pastebin.com/') or url.startswith('http://pastebin.com/')):
                            print(f"       [⏭️ ] SKIPPED - Not a valid PasteBin URL\n")
                            continue
                        
                        # Duplicate check
                        if url in found_urls:
                            print(f"       [⏭️ ] SKIPPED - Duplicate URL\n")
                            continue
                        
                        found_urls.add(url)
                        
                        # Content verification (SpiderFoot style)
                        print(f"       [*] Verifying content...")
                        
                        try:
                            # Convert to raw paste URL
                            if '/raw/' not in url:
                                paste_id = url.split('/')[-1].split('?')[0]
                                raw_url = f'https://pastebin.com/raw/{paste_id}'
                            else:
                                raw_url = url
                            
                            content_response = requests.get(raw_url, timeout=15)
                            
                            if content_response.status_code == 200:
                                content = content_response.text
                                
                                # SpiderFoot-style pattern matching
                                pattern = r"[^a-zA-Z\-\_0-9]" + re.escape(domain) + r"[^a-zA-Z\-\_0-9]"
                                
                                if re.search(pattern, content, re.IGNORECASE):
                                    leak_entry = {
                                        'title': title,
                                        'url': url,
                                        'snippet': snippet,
                                        'verified': True,
                                        'content_length': len(content),
                                        'content_preview': content[:300] + "..." if len(content) > 300 else content
                                    }
                                    verified_leaks.append(leak_entry)
                                    print(f"       [✅] VERIFIED - Leak detected!")
                                    print(f"       [📄] Content length: {len(content)} characters\n")
                                else:
                                    print(f"       [⏭️ ] SKIPPED - Domain not found in actual content\n")
                            else:
                                print(f"       [⏭️ ] SKIPPED - Could not fetch content (HTTP {content_response.status_code})\n")
                        
                        except Exception as e:
                            print(f"       [⏭️ ] SKIPPED - Fetch error: {str(e)}\n")
                            continue
                    
                    print("  " + "="*76)
                    print(f"  [SUMMARY]")
                    print(f"    Total found by Google: {total_found}")
                    print(f"    Verified leaks: {len(verified_leaks)}")
                    print(f"    Skipped (no match): {total_found - len(verified_leaks)}")
                    print("  " + "="*76)
                    print()
                    
                    return {
                        'status': 'success',
                        'domain': domain,
                        'total_google_results': total_found,
                        'verified_leaks': verified_leaks,
                        'verified_count': len(verified_leaks)
                    }
                else:
                    print(f"  [!] No results found for '{domain}'\n")
                    return {
                        'status': 'no_results',
                        'domain': domain,
                        'verified_leaks': [],
                        'verified_count': 0
                    }
            
            elif response.status_code == 403:
                print("  [ERROR] Invalid API key or quota exceeded\n")
                return {'status': 'error', 'message': 'API key invalid or quota exceeded'}
            
            elif response.status_code == 429:
                print("  [ERROR] Rate limit exceeded\n")
                return {'status': 'error', 'message': 'Rate limit exceeded'}
            
            else:
                print(f"  [ERROR] HTTP Status Code: {response.status_code}\n")
                return {'status': 'error', 'message': f'HTTP {response.status_code}'}
        
        except Exception as e:
            print(f"  [ERROR] {str(e)}\n")
            return {'status': 'error', 'message': str(e)}
        

    def query_intelligencex(self, domain: str) -> dict:
        """
        IntelligenceX - Dark web and breach intelligence
        Shows first 5 results + provides all data for download
        """
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[INTELLIGENCE X] DARK WEB & BREACH SEARCH")
        print("="*80)
        print()
        
        try:
            intelx_config = APPLICATION_LANDSCAPE_APIS.get('leaks', {}).get('intelx', {})
            
            if not intelx_config.get('enabled', False):
                print("  IntelligenceX API disabled\n")
                return {'status': 'disabled'}
            
            api_key = intelx_config.get('api_key', '')
            base_url = intelx_config.get('base_url', 'free.intelx.io')
            maxresults = intelx_config.get('maxresults', 100)
            
            headers = {
                'User-Agent': 'BSI-Scanner',
                'x-key': api_key,
                'Content-Type': 'application/json'
            }
            
            payload = {
                "term": domain,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": maxresults,
                "timeout": 0,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": []
            }
            
            results = {
                'status': 'active',
                'domain': domain,
                'all_results': [],
                'total_records': 0,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Intelligent Search
            print(f"  Searching for: {domain} (type: intelligent)")
            
            try:
                url = f'https://{base_url}/intelligent/search'
                response = requests.post(url, json=payload, headers=headers, timeout=30)
                
                if response.status_code == 402:
                    return {'status': 'error', 'message': 'Credits expired'}
                if response.status_code == 401:
                    return {'status': 'error', 'message': 'Authentication failed'}
                if response.status_code != 200:
                    return {'status': 'error', 'message': f'HTTP {response.status_code}'}
                
                data = response.json()
                search_id = data.get('id')
                
                if not search_id:
                    return results
                
                print(f"  Search ID: {search_id}, polling for results...")
                
                # Poll for results
                result_url = f"{url}/result?id={search_id}"
                
                for _ in range(30):
                    time.sleep(1)
                    
                    result_response = requests.get(result_url, headers=headers, timeout=15)
                    
                    if result_response.status_code != 200:
                        break
                    
                    result_data = result_response.json()
                    status = result_data.get('status', -1)
                    records = result_data.get('records', [])
                    
                    # Process records
                    for rec in records:
                        try:
                            bucket = rec.get('bucket', 'N/A')
                            systemid = rec.get('systemid', '')
                            
                            # Determine type
                            record_type = "leak" if "pastes" in bucket else "darknet"
                            
                            # Create result entry
                            result_entry = {
                                'type': record_type,
                                'bucket': bucket,
                                'added': rec.get('added', 'N/A'),
                                'name': rec.get('name', 'N/A'),
                                'url': f"https://intelx.io/?did={systemid}" if systemid else 'N/A'
                            }
                            
                            results['all_results'].append(result_entry)
                            results['total_records'] += 1
                        
                        except:
                            continue
                    
                    if len(records) > 0:
                        print(f"  Found {len(records)} records in this batch")
                    
                    if status == 1:  # Complete
                        print("  Search completed!")
                        break
                    elif status in [0, 3]:
                        continue
                    else:
                        break
                
                print(f"\n  [+] Total results found: {results['total_records']}")
                
                # Display first 5 in terminal
                if results['all_results']:
                    print()
                    for idx, result in enumerate(results['all_results'][:5], 1):
                        print(f"  Result {idx}:")
                        print(f"    Type: {result['type']}")
                        print(f"    Bucket: {result['bucket']}")
                        print(f"    Added: {result['added']}")
                        print(f"    URL: {result['url']}")
                        print()
                
                print()
                
            except Exception as e:
                print(f"  [ERROR] {str(e)}\n")
            
            return results
            
        except Exception as e:
            print(f"  [ERROR] {str(e)}\n")
            return {'status': 'error', 'message': str(e)}
        

    def query_projecthoneypot(self, domain: str) -> dict:
        """
        Project Honey Pot - DNS-based IP reputation checking
        Enhanced: Checks ALL IPs for the domain
        """
        if not API_CONFIG_AVAILABLE:
            return {}
        
        print("="*80)
        print("[PROJECT HONEYPOT] IP REPUTATION CHECK")
        print("="*80)
        print()
        
        try:
            honeypot_config = APPLICATION_LANDSCAPE_APIS.get('threat_intel', {}).get('projecthoneypot', {})
            
            if not honeypot_config.get('enabled', False):
                print("  Project Honey Pot API disabled\n")
                return {'status': 'disabled'}
            
            api_key = honeypot_config.get('api_key', '')
            threatscore = honeypot_config.get('threatscore', 0)
            timelimit = honeypot_config.get('timelimit', 30)
            search_engine = honeypot_config.get('search_engine', False)
            
            # Status codes
            statuses = {
                "0": "Search Engine",
                "1": "Suspicious",
                "2": "Harvester",
                "3": "Suspicious & Harvester",
                "4": "Comment Spammer",
                "5": "Suspicious & Comment Spammer",
                "6": "Harvester & Comment Spammer",
                "7": "Suspicious & Harvester & Comment Spammer",
                "8": "Unknown (8)",
                "9": "Unknown (9)",
                "10": "Unknown (10)"
            }
            
            def reverse_ip(ip):
                return '.'.join(reversed(ip.split('.')))
            
            def parse_dns(addr, ip):
                try:
                    bits = addr.split(".")
                    days_old = int(bits[1])
                    threat_level = int(bits[2])
                    visitor_type = bits[3]
                    
                    # Apply filters
                    if days_old > timelimit:
                        return None
                    if threat_level < threatscore:
                        return None
                    if visitor_type == "0" and not search_engine:
                        return None
                    
                    # Determine severity
                    if visitor_type == "0":
                        severity = "INFO"
                    elif threat_level > 100:
                        severity = "HIGH"
                    elif threat_level > 50:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    
                    return {
                        'ip': ip,
                        'status': statuses.get(visitor_type, f"Unknown ({visitor_type})"),
                        'days_since_activity': days_old,
                        'threat_level': threat_level,
                        'severity': severity,
                        'url': f"https://www.projecthoneypot.org/ip_{ip}"
                    }
                except:
                    return None
            
            # ✅ STEP 1: Resolve domain to ALL IPs
            print(f"  [STEP 1] Resolving domain to ALL IP addresses...")
            print(f"    Domain: {domain}")
            
            try:
                import socket
                # ✅ Use getaddrinfo to get ALL IPs (not just first one)
                addr_info = socket.getaddrinfo(domain, None)
                
                # Extract unique IPs
                ip_addresses = list(set([addr[4][0] for addr in addr_info]))
                
                print(f"    ✅ Found {len(ip_addresses)} IP(s):")
                for ip in ip_addresses:
                    print(f"       • {ip}")
                print()
                
            except socket.gaierror as e:
                print(f"    ❌ Failed to resolve: {str(e)}\n")
                return {
                    'status': 'error',
                    'domain': domain,
                    'message': f'DNS resolution failed: {str(e)}'
                }
            
            # ✅ STEP 2: Check ALL IPs against honeypot
            print(f"  [STEP 2] Checking {len(ip_addresses)} IP(s) against Project Honey Pot...")
            print()
            
            results = {
                'status': 'active',
                'domain': domain,
                'ip_addresses': ip_addresses,
                'total_ips': len(ip_addresses),
                'threats': [],
                'clean_ips': [],
                'checked_ips': []
            }
            
            for idx, ip_address in enumerate(ip_addresses, 1):
                print(f"  [{idx}/{len(ip_addresses)}] Checking: {ip_address}")
                
                try:
                    lookup = f"{api_key}.{reverse_ip(ip_address)}.dnsbl.httpbl.org"
                    
                    # DNS lookup
                    hostname, aliases, ip_list = socket.gethostbyname_ex(lookup)
                    
                    # Parse response
                    threat_found = False
                    for response_ip in ip_list:
                        threat = parse_dns(response_ip, ip_address)
                        if threat:
                            results['threats'].append(threat)
                            print(f"       [!!!] THREAT: {threat['status']} (Severity: {threat['severity']})")
                            threat_found = True
                            break
                    
                    if not threat_found:
                        results['clean_ips'].append(ip_address)
                        print(f"       [✓] Clean")
                    
                    results['checked_ips'].append(ip_address)
                    
                except socket.gaierror:
                    # Not in database = clean
                    results['clean_ips'].append(ip_address)
                    results['checked_ips'].append(ip_address)
                    print(f"       [✓] Clean (not in database)")
                except Exception as e:
                    print(f"       [!] Error: {str(e)}")
                
                print()



            
            # Summary
            print("  " + "="*76)
            print(f"  [SUMMARY]")
            print(f"    Domain: {domain}")
            print(f"    Total IPs: {results['total_ips']}")
            print(f"    Checked IPs: {len(results['checked_ips'])}")
            print(f"    Threats Found: {len(results['threats'])}")
            print(f"    Clean IPs: {len(results['clean_ips'])}")
            print(f"    Status: {'⚠️ THREATS DETECTED' if results['threats'] else '✅ ALL CLEAN'}")
            print("  " + "="*76)
            print()
            
            return results
            
        except Exception as e:
            print(f"  [ERROR] {str(e)}\n")
            return {'status': 'error', 'message': str(e)}



    
    # ============================================================================
    # PHASE 3: 3 NEW THREAT INTELLIGENCE APIs
    # ============================================================================

    def check_virustotal_v2(self, domain: str = None, ip: str = None) -> dict:
        """
        Check domain/IP against VirusTotal database (SYNC)
        Returns: malware detection, verdict, vendor count
        """
        try:
            from bsi_api_config import APPLICATION_LANDSCAPE_APIS
            config = APPLICATION_LANDSCAPE_APIS.get('threat_intel', {}).get('virustotal', {})
            api_key = config.get('api_key')

            if not api_key or api_key == 'your_virustotal_api_key_here':
                logger.warning("⚠️ VirusTotal API key not configured")
                return {"status": "not_configured"}

            headers = {"x-apikey": api_key}

            # Check domain
            if domain:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    return {
                        "domain": domain,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                    }

            # Check IP
            if ip:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    return {
                        "ip": ip,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                    }
        except Exception as e:
            logger.debug(f"VirusTotal check failed: {e}")

        return {}


    def check_pulsedive_threat(self, ip: str = None, domain: str = None) -> dict:
        """
        Check threat risk assessment from Pulsedive (SYNC)
        Returns: threat level, risk score
        """
        try:
            from bsi_api_config import APPLICATION_LANDSCAPE_APIS
            config = APPLICATION_LANDSCAPE_APIS.get('threat_intel', {}).get('pulsedive', {})
            api_key = config.get('api_key')
            
            if not api_key or api_key == 'your_pulsedive_api_key_here':
                logger.warning("⚠️ Pulsedive API key not configured")
                return {"status": "not_configured"}
            
            # Search for IP or domain
            search_value = ip if ip else domain
            url = f"https://pulsedive.com/api/v2/search.php?q={search_value}&key={api_key}"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('results'):
                    threat = data['results']
                    return {
                        "target": search_value,
                        "threat_level": threat.get('threat', 'unknown'),
                        "risk_score": threat.get('risk', 0),
                        "stamp": threat.get('stamp', 0),
                    }
        except Exception as e:
            logger.debug(f"Pulsedive check failed: {e}")
        
        return {}


    def check_viewdns_reverse_ip(self, ip: str) -> dict:
        """
        Get all domains hosted on same IP using ViewDNS (SYNC)
        Returns: list of co-hosted domains
        """
        try:
            from bsi_api_config import APPLICATION_LANDSCAPE_APIS
            config = APPLICATION_LANDSCAPE_APIS.get('dns', {}).get('viewdns', {})
            apikey = config.get('api_key', '')
            url = f"https://api.viewdns.net/reverseip/?ip={ip}&apikey={apikey}&output=json"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('response'):
                    domains = [d.get('domain') for d in data['response']]
                    return {
                        "ip": ip,
                        "co_hosted_domains": domains,
                        "count": len(domains),
                    }
        except Exception as e:
            logger.debug(f"ViewDNS reverse IP failed: {e}")
        
        return {}


    def generate_report(self, filename=None):
        """Generate comprehensive JSON report with all Phase 3 findings"""
        import os
        os.makedirs("reports", exist_ok=True)
        if filename is None:
            filename = os.path.join("reports", f"BSI_Phase3_Application_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        print("\n" + "="*80)
        print("SCAN COMPLETE - BSI STAGE 3 REPORT")
        print("="*80 + "\n")
        
        print("SUMMARY:")
        
        stack = self.results.get('2_web_server_stack', {})
        print(f"\n   Technologies: {len(stack.get('all_detected', []))}")
        
        if stack.get('cms'):
            cms_version = f" {stack.get('cms_version')}" if stack.get('cms_version') else ""
            print(f"   CMS: {', '.join(stack['cms'])}{cms_version}")
        
        if stack.get('javascript_versions'):
            print(f"   JS Libraries:")
            for lib, ver in stack['javascript_versions'].items():
                print(f"      {lib} {ver}")
        
        repos = self.results.get('5_code_repositories', {})
        print(f"   Exposed Files: {len(repos.get('exposed_files', []))}")
        print(f"   GitHub Repos: {len(repos.get('github_repos', []))}")
        robots_dis = repos.get('robots_disallow', [])
        if robots_dis:
            print(f"   Robots Disallow Paths: {len(robots_dis)}")
        robots_sm = repos.get('robots_sitemaps', [])
        if robots_sm:
            print(f"   Sitemaps Found: {len(robots_sm)}")

        vuln = self.results.get('6_outdated_software', {})
        print(f"   Vulnerable Libraries: {vuln.get('count', 0)}")

        security = self.results.get('7_security_posture', {})
        if security:
            missing_headers = sum(1 for h in security.get('security_headers', {}).values() if not h.get('present'))
            total_headers = len(security.get('security_headers', {}))
            print(f"   Security Headers: {total_headers - missing_headers}/{total_headers}")
            print(f"   Admin Panels Found: {len(security.get('admin_panels', []))} (only 200/401/403)")
            header_issues = security.get('header_issues', [])
            if header_issues:
                print(f"   Header Issues: {len(header_issues)}")
            js_maps = security.get('js_sourcemaps', [])
            if js_maps:
                print(f"   JS Source Maps Exposed: {len(js_maps)}")
            open_red = security.get('open_redirect', [])
            if open_red:
                print(f"   Open Redirect Params: {len(open_red)}")

        api_disc = self.results.get('8_api_discovery', {})
        if api_disc:
            total_apis = len(api_disc.get('api_endpoints', [])) + len(api_disc.get('graphql_endpoints', [])) + len(api_disc.get('api_documentation', []))
            print(f"   API Endpoints: {total_apis} (only 200 status)")
            av = api_disc.get('active_api_versions', {})
            if av:
                for base, vers in av.items():
                    print(f"   Active API Versions ({base}): {', '.join(vers)}")

        erp = self.results.get('3_erp_sap_detection', {})
        if erp and erp.get('detected_systems'):
            print(f"   ERP/SAP: {', '.join(erp.get('detected_systems', []))}")
            erp_vers = erp.get('erp_versions', {})
            if erp_vers:
                for name, ver in erp_vers.items():
                    print(f"      {name} version: {ver}")

        db = self.results.get('9_database_detection', {})
        if db and db.get('database_type'):
            print(f"   Database: {', '.join(db.get('database_type', []))}")
        conn_str = db.get('connection_strings', []) if db else []
        if conn_str:
            print(f"   ⚠️  Exposed DB Connection Strings: {len(conn_str)}")

        # New sections: Threat Intelligence, Leak Detection, S3 Exposure
        threat = self.results.get('10_threat_intelligence', {})
        if threat:
            vt = threat.get('virustotal', {})
            if vt.get('malicious', 0):
                print(f"   VirusTotal Malicious: {vt['malicious']}")
            pd = threat.get('pulsedive', {})
            if pd.get('risk') and pd['risk'] not in ('unknown', 'none'):
                print(f"   Pulsedive Risk: {pd['risk']}")

        leaks = self.results.get('11_leak_detection', {})
        if leaks:
            emails = leaks.get('breached_emails', [])
            if emails:
                print(f"   Breached Emails Found: {len(emails)}")
            pastes = leaks.get('pastebin_results', [])
            if pastes:
                print(f"   Pastebin Leaks: {len(pastes)}")

        s3 = self.results.get('12_s3_exposure', {})
        if s3:
            buckets = s3.get('exposed_buckets', [])
            if buckets:
                print(f"   Exposed S3 Buckets: {len(buckets)}")

        # SRI missing (stored in 7_security_posture)
        sri_missing = security.get('sri_missing', []) if security else []
        if sri_missing:
            print(f"   Scripts Missing SRI: {len(sri_missing)}")

        # Client-side secrets
        tp = self.results.get('4_third_party_software', {})
        secrets = tp.get('exposed_secrets', [])
        if secrets:
            print(f"   ⚠️  Client-Side Secrets Found: {len(secrets)}")

        print(f"\n   Report: {filename}\n")
        
        return filename


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("\n" + "="*80)
    print("BSI STAGE 3 - COMPLETE OSINT SCANNER (FINAL)")
    print("="*80 + "\n")
    
    domain = input("Enter domain (e.g., example.com): ").strip()
    
    if not domain:
        print("Domain required!")
        sys.exit(1)
    
    print(f"\nStarting scan of {domain}...\n")
    
    scanner = CompleteBSIScanner(domain)
    results = scanner.run_full_scan()
    report_file = scanner.generate_report()
    
    print("Scan complete!\n")