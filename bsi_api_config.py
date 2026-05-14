#!/usr/bin/env python3
"""
BSI API Configuration - Centralized configuration for all API keys and endpoints
All secrets are loaded from .env — never hardcoded here.
"""

try:
    from dotenv import load_dotenv
    from pathlib import Path
    load_dotenv(dotenv_path=Path(__file__).parent / '.env')
except ImportError:
    pass

import os


# =============================================================================
# PHASE 1: BUSINESS DOMAIN UNDERSTANDING
# =============================================================================

BUSINESS_DOMAIN_APIS = {
    'company_enrichment': {
        'name': 'AbstractAPI Company Enrichment',
        'api_key': os.getenv('ABSTRACTAPI_COMPANY_KEY', ''),
        'endpoint': 'https://companyenrichment.abstractapi.com/v1/',
        'enabled': True
    },
    'email_finder': {
        'name': 'Hunter.io',
        'api_key': os.getenv('HUNTER_IO_KEY', ''),
        'endpoint': 'https://api.hunter.io/v2/domain-search',
        'enabled': True
    },
    'domain_info': {
        'name': 'Host.io',
        'api_key': os.getenv('HOST_IO_KEY', ''),
        'endpoint': 'https://host.io/api/full/',
        'enabled': True
    }
}


# =============================================================================
# PHASE 2: INFRASTRUCTURE DISCOVERY
# =============================================================================

INFRA_DISCOVERY_APIS = {
    'ip_geolocation': {
        'abstractapi_ip': {
            'name': 'AbstractAPI IP Geolocation',
            'api_key': os.getenv('ABSTRACTAPI_IP_KEY', ''),
            'endpoint': 'https://ipgeolocation.abstractapi.com/v1/',
            'enabled': True
        },
        'ipinfo': {
            'name': 'IPInfo',
            'api_key': os.getenv('IPINFO_KEY', ''),
            'endpoint': 'https://ipinfo.io/',
            'enabled': True
        },
        'ipregistry': {
            'name': 'IPRegistry',
            'api_key': os.getenv('IPREGISTRY_KEY', ''),
            'endpoint': 'https://api.ipregistry.co/',
            'enabled': True
        },
        'neutrinoapi': {
            'name': 'NeutrinoAPI',
            'user_id': os.getenv('NEUTRINO_USER_ID', ''),
            'api_key': os.getenv('NEUTRINO_API_KEY', ''),
            'endpoint': 'https://neutrinoapi.com/ip-info',
            'enabled': True
        }
    },

    'network': {
        'name': 'NetworksDB',
        'api_key': os.getenv('NETWORKSDB_KEY', ''),
        'endpoint': 'https://networksdb.io/api/ip-info',
        'enabled': True
    },

    'ssl': {
        'name': 'CertSpotter',
        'api_key': os.getenv('CERTSPOTTER_KEY', ''),
        'endpoint': 'https://api.certspotter.com/v1/issuances',
        'enabled': True
    },

    'subdomains': {
        'fullhunt': {
            'name': 'FullHunt',
            'api_key': os.getenv('FULLHUNT_KEY', ''),
            'endpoint': 'https://fullhunt.io/api/v1/domain/',
            'enabled': True
        },
        'projectdiscovery': {
            'name': 'ProjectDiscovery Chaos',
            'api_key': os.getenv('PROJECTDISCOVERY_KEY', ''),
            'endpoint': 'https://dns.projectdiscovery.io/dns/',
            'enabled': True
        }
    },

    'spiderfoot_apis': {
        'abusix': {
            'name': 'Abusix',
            'apikey': os.getenv('ABUSIX_KEY', ''),
            'endpoint': 'dns',
            'enabled': True
        },
        'ipstack': {
            'name': 'IPStack',
            'api_key': os.getenv('IPSTACK_KEY', ''),
            'endpoint': 'http://api.ipstack.com/',
            'enabled': True
        },
        'ipapicom': {
            'name': 'ipapi.com',
            'api_key': os.getenv('IPAPI_KEY', ''),
            'endpoint': 'http://api.ipapi.com/api/',
            'enabled': True
        },
        'fraudguard': {
            'name': 'FraudGuard',
            'username': os.getenv('FRAUDGUARD_USERNAME', ''),
            'password': os.getenv('FRAUDGUARD_PASSWORD', ''),
            'endpoint': 'https://api.fraudguard.io/ip/',
            'enabled': True
        }
    },

    'phone': {
        'numverify': {
            'name': 'NumVerify',
            'api_key': os.getenv('NUMVERIFY_KEY', ''),
            'endpoint': 'http://apilayer.net/api/validate',
            'enabled': True
        },
        'twilio': {
            'name': 'Twilio',
            'account_sid': os.getenv('TWILIO_ACCOUNT_SID', ''),
            'auth_token': os.getenv('TWILIO_AUTH_TOKEN', ''),
            'endpoint': 'https://api.twilio.com/2010-04-01/Accounts/',
            'enabled': True
        }
    }
}


# =============================================================================
# PHASE 3: APPLICATION LANDSCAPE & THREAT INTELLIGENCE
# =============================================================================

APPLICATION_LANDSCAPE_APIS = {
    'whatcms': {
        'name': 'WhatCMS',
        'api_key': os.getenv('WHATCMS_KEY', ''),
        'endpoint': 'https://whatcms.org/API/Tech',
        'enabled': True
    },

    'exposure': {
        'name': 'GrayHatWarfare',
        'api_key': os.getenv('GRAYHATWARFARE_KEY', ''),
        'endpoint': 'https://buckets.grayhatwarfare.com/api/v1/files',
        'enabled': True
    },

    'threat_intel': {
        'metadefender': {
            'name': 'MetaDefender',
            'api_key': os.getenv('METADEFENDER_KEY', ''),
            'endpoint': 'https://api.metadefender.com/v4/ip/',
            'enabled': True
        },
        'abuseipdb': {
            'name': 'AbuseIPDB',
            'api_key': os.getenv('ABUSEIPDB_KEY', ''),
            'endpoint': 'https://api.abuseipdb.com/api/v2/check',
            'enabled': True
        },
        'alienvault': {
            'name': 'AlienVault OTX',
            'api_key': os.getenv('ALIENVAULT_KEY', ''),
            'endpoint': 'https://otx.alienvault.com/api/v1/indicators/IPv4/',
            'enabled': True
        },
        'greynoise': {
            'name': 'GreyNoise',
            'api_key': os.getenv('GREYNOISE_KEY', ''),
            'endpoint': 'https://api.greynoise.io/v3/community/',
            'enabled': True
        },
        'projecthoneypot': {
            'name': 'Project Honey Pot',
            'api_key': os.getenv('PROJECTHONEYPOT_KEY', ''),
            'endpoint': 'dnsbl.httpbl.org',
            'enabled': True,
            'search_engine': False,
            'threatscore': 0,
            'timelimit': 30
        },
        'virustotal': {
            'name': 'VirusTotal',
            'api_key': os.getenv('VIRUSTOTAL_KEY', ''),
            'endpoint': 'https://www.virustotal.com/api/v3/',
            'enabled': True
        },
        'pulsedive': {
            'name': 'Pulsedive',
            'api_key': os.getenv('PULSEDIVE_KEY', ''),
            'endpoint': 'https://pulsedive.com/api/v2/',
            'enabled': True
        },
    },

    'dns': {
        'viewdns': {
            'name': 'ViewDNS',
            'api_key': os.getenv('VIEWDNS_KEY', ''),
            'endpoint': 'https://api.viewdns.net/',
            'enabled': True
        }
    },

    'leaks': {
        'citadel': {
            'name': 'Citadel (leak-lookup.com)',
            'api_key': os.getenv('LEAKLOOKUP_KEY', ''),
            'endpoint': 'https://leak-lookup.com/api/search',
            'enabled': True
        },
        'leakix': {
            'name': 'LeakIX',
            'api_key': os.getenv('LEAKIX_KEY', ''),
            'endpoint': 'https://leakix.net/host/',
            'enabled': True
        },
        'pastebin_search': {
            'name': 'PasteBin Leak Detection',
            'api_key': os.getenv('GOOGLE_CSE_KEY', ''),
            'cse_id': os.getenv('GOOGLE_CSE_ID', ''),
            'endpoint': 'https://www.googleapis.com/customsearch/v1',
            'enabled': True
        },
        'intelx': {
            'name': 'IntelligenceX Dark Web & Breach Data',
            'api_key': os.getenv('INTELX_KEY', ''),
            'base_url': 'free.intelx.io',
            'endpoint': 'https://free.intelx.io',
            'enabled': True,
            'maxage': 0,
            'maxresults': 100
        }
    }
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_total_api_count():
    """Count total enabled APIs"""
    count = 0
    count += len([k for k, v in BUSINESS_DOMAIN_APIS.items() if v.get('enabled')])

    for category in INFRA_DISCOVERY_APIS.values():
        if isinstance(category, dict):
            if 'enabled' in category:
                count += 1
            else:
                count += len([k for k, v in category.items() if v.get('enabled')])

    for category in APPLICATION_LANDSCAPE_APIS.values():
        if isinstance(category, dict):
            if 'enabled' in category:
                count += 1
            else:
                count += len([k for k, v in category.items() if v.get('enabled')])

    return count


if __name__ == "__main__":
    print("=" * 80)
    print("BSI API CONFIGURATION")
    print("=" * 80)
    print(f"\n✅ Total Enabled APIs: {get_total_api_count()}")
    print("\nPhase 1 - Business Domain Understanding: 3 APIs")
    print("\nPhase 2 - Infrastructure Discovery: 11 APIs")
    print("\nPhase 3 - Application Landscape & Threats: 11 APIs")
    print("\n" + "=" * 80)
