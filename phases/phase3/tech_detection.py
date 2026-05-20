"""
Phase 3: Technology Detection
Handles detection of web technologies, frameworks, and CMS
"""

import logging
import re
import os
import requests
from typing import Dict, List, Any
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; BSI-Scanner/1.0)'}


class TechDetection:
    """Handles technology detection"""

    def detect_cms(self, domain: str) -> Dict[str, Any]:
        """Detect CMS used by website"""
        try:
            resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=15, allow_redirects=True)
            soup = BeautifulSoup(resp.content, 'html.parser')
            content = resp.text
            headers = resp.headers
            cms_detected = []

            # WordPress
            if (soup.find('link', href=re.compile(r'wp-content|wp-includes', re.I)) or
                    '/wp-json/' in content or 'wp-embed' in content):
                cms_detected.append('WordPress')

            # Drupal
            if (soup.find('meta', attrs={'name': 'Generator', 'content': re.compile(r'Drupal', re.I)}) or
                    'Drupal.settings' in content or '/sites/default/files/' in content):
                cms_detected.append('Drupal')

            # Joomla
            if (soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Joomla', re.I)}) or
                    '/components/com_' in content):
                cms_detected.append('Joomla')

            # Shopify
            if 'cdn.shopify.com' in content or 'Shopify.theme' in content:
                cms_detected.append('Shopify')

            # Wix
            if 'wix.com' in content or '_wix_' in content:
                cms_detected.append('Wix')

            # Squarespace
            if 'squarespace.com' in content or 'squarespace-cdn.com' in content:
                cms_detected.append('Squarespace')

            # Webflow
            if 'webflow.com' in content or 'webflow.io' in content:
                cms_detected.append('Webflow')

            # Ghost
            if 'ghost.io' in content or '/ghost/' in content:
                cms_detected.append('Ghost')

            # Magento
            if 'Mage.Cookies' in content or '/skin/frontend/' in content or 'magento' in content.lower():
                cms_detected.append('Magento')

            # PrestaShop
            if 'prestashop' in content.lower() or '/modules/ps_' in content:
                cms_detected.append('PrestaShop')

            # WooCommerce (WordPress plugin)
            if 'woocommerce' in content.lower() and 'WordPress' in cms_detected:
                cms_detected.append('WooCommerce')

            # Typo3
            if 'typo3' in content.lower() or 'typo3conf' in content:
                cms_detected.append('TYPO3')

            # Contentful
            if 'contentful.com' in content:
                cms_detected.append('Contentful')

            # HubSpot CMS
            if 'hs-scripts.com' in content or 'hubspot.com/hs-fs' in content:
                cms_detected.append('HubSpot CMS')

            # Try WhatCMS API if key available
            whatcms_key = os.getenv('WHATCMS_KEY')
            if whatcms_key and not cms_detected:
                try:
                    api_resp = requests.get(
                        'https://whatcms.org/API/Tech',
                        params={'key': whatcms_key, 'url': f'https://{domain}'},
                        timeout=10
                    )
                    if api_resp.status_code == 200:
                        api_data = api_resp.json()
                        for tech in api_data.get('result', {}).get('technologies', []):
                            name = tech.get('name', '')
                            if name and name not in cms_detected:
                                cms_detected.append(name)
                except Exception as e:
                    logger.debug(f"WhatCMS API failed: {e}")

            return {'cms': cms_detected, 'success': True}
        except Exception as e:
            logger.error(f"CMS detection failed: {e}")
            return {'cms': [], 'success': False, 'error': str(e)}

    def detect_frameworks(self, domain: str) -> Dict[str, Any]:
        """Detect web frameworks from headers and page content"""
        try:
            resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=15, allow_redirects=True)
            content = resp.text
            h = resp.headers
            frameworks = []

            # From headers
            for header in ['X-Powered-By', 'Server', 'X-Generator', 'X-Framework']:
                val = h.get(header, '')
                if val:
                    frameworks.append(val)

            # From content patterns
            fw_patterns = [
                (r'laravel', 'Laravel'),
                (r'symfony', 'Symfony'),
                (r'django', 'Django'),
                (r'flask', 'Flask'),
                (r'rails|ruby on rails', 'Ruby on Rails'),
                (r'asp\.net', 'ASP.NET'),
                (r'next\.js|__next', 'Next.js'),
                (r'nuxt\.js|__nuxt', 'Nuxt.js'),
                (r'gatsby', 'Gatsby'),
                (r'spring boot|springboot', 'Spring Boot'),
                (r'express\.js|expressjs', 'Express.js'),
                (r'fastapi', 'FastAPI'),
                (r'codeigniter', 'CodeIgniter'),
                (r'yii framework', 'Yii'),
                (r'cakephp', 'CakePHP'),
            ]
            for pattern, name in fw_patterns:
                if re.search(pattern, content, re.IGNORECASE) and name not in frameworks:
                    frameworks.append(name)

            return {'frameworks': list(dict.fromkeys(frameworks)), 'success': True}
        except Exception as e:
            logger.error(f"Framework detection failed: {e}")
            return {'frameworks': [], 'success': False, 'error': str(e)}

    def detect_javascript_libraries(self, domain: str) -> Dict[str, Any]:
        """Detect JavaScript libraries from script tags and content"""
        try:
            resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=15, allow_redirects=True)
            soup = BeautifulSoup(resp.content, 'html.parser')
            content = resp.text
            libraries = []

            # From script src attributes
            src_patterns = [
                (r'jquery', 'jQuery'),
                (r'react(?:\.min)?\.js|react-dom', 'React'),
                (r'vue(?:\.min)?\.js', 'Vue.js'),
                (r'angular(?:\.min)?\.js', 'Angular'),
                (r'backbone(?:\.min)?\.js', 'Backbone.js'),
                (r'ember(?:\.min)?\.js', 'Ember.js'),
                (r'lodash|underscore', 'Lodash/Underscore'),
                (r'moment(?:\.min)?\.js', 'Moment.js'),
                (r'axios(?:\.min)?\.js', 'Axios'),
                (r'bootstrap(?:\.min)?\.js', 'Bootstrap JS'),
                (r'tailwind', 'Tailwind CSS'),
                (r'three(?:\.min)?\.js', 'Three.js'),
                (r'd3(?:\.min)?\.js', 'D3.js'),
                (r'chart(?:\.min)?\.js', 'Chart.js'),
                (r'socket\.io', 'Socket.IO'),
                (r'alpinejs|alpine\.js', 'Alpine.js'),
                (r'htmx', 'HTMX'),
                (r'svelte', 'Svelte'),
            ]

            for script in soup.find_all('script', src=True):
                src = script.get('src', '').lower()
                for pattern, name in src_patterns:
                    if re.search(pattern, src) and name not in libraries:
                        libraries.append(name)

            # From inline content
            for pattern, name in src_patterns:
                if re.search(pattern, content, re.IGNORECASE) and name not in libraries:
                    libraries.append(name)

            return {'libraries': libraries, 'success': True}
        except Exception as e:
            logger.error(f"JavaScript library detection failed: {e}")
            return {'libraries': [], 'success': False, 'error': str(e)}
