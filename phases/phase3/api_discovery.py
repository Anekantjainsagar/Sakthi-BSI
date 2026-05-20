"""
Phase 3: API Discovery
Handles discovery of API endpoints and documentation
"""

import logging
import requests
from typing import Dict, List, Any

logger = logging.getLogger(__name__)
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; BSI-Scanner/1.0)'}


class APIDiscovery:
    """Handles API endpoint discovery"""

    # Common API paths to probe
    API_PATHS = [
        '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
        '/api/v1/', '/api/v2/', '/api/v3/',
        '/rest', '/rest/', '/rest/v1', '/rest/v2',
        '/v1', '/v2', '/v3',
        '/service', '/services', '/webservice', '/webservices',
        '/json', '/xml',
        '/api/users', '/api/products', '/api/orders',
        '/api/health', '/api/status', '/api/ping',
        '/api/docs', '/api/documentation',
        '/api/schema', '/api/spec',
        '/api/auth', '/api/login', '/api/token',
        '/api/search', '/api/data',
        '/api/public', '/api/private',
        '/api/admin', '/api/internal',
        '/api/v1/users', '/api/v1/products',
        '/api/v2/users', '/api/v2/products',
        '/wp-json', '/wp-json/wp/v2',
        '/jsonapi', '/odata',
    ]

    SWAGGER_PATHS = [
        '/swagger', '/swagger/', '/swagger-ui', '/swagger-ui/',
        '/swagger-ui.html', '/swagger/index.html',
        '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
        '/api-docs', '/api-docs/', '/api/docs',
        '/openapi', '/openapi.json', '/openapi.yaml',
        '/api/swagger.json', '/api/openapi.json',
        '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
        '/redoc', '/redoc/',
        '/docs', '/docs/',
    ]

    GRAPHQL_PATHS = [
        '/graphql', '/graphql/', '/api/graphql',
        '/gql', '/query', '/api/query',
    ]

    def discover_api_endpoints(self, domain: str) -> Dict[str, Any]:
        """Probe common API paths"""
        endpoints = []
        for path in self.API_PATHS:
            try:
                resp = requests.get(
                    f"https://{domain}{path}", headers=HEADERS,
                    timeout=5, allow_redirects=False
                )
                if resp.status_code in (200, 201, 400, 401, 403, 405):
                    content_type = resp.headers.get('Content-Type', '')
                    is_json = 'json' in content_type or 'javascript' in content_type
                    endpoints.append({
                        'path': path,
                        'status': resp.status_code,
                        'content_type': content_type,
                        'is_json': is_json,
                        'accessible': resp.status_code in (200, 201),
                    })
            except Exception:
                pass
        return {'api_endpoints': endpoints, 'success': True}

    def discover_graphql(self, domain: str) -> Dict[str, Any]:
        """Discover GraphQL endpoints"""
        endpoints = []
        for path in self.GRAPHQL_PATHS:
            try:
                # Introspection probe
                resp = requests.post(
                    f"https://{domain}{path}",
                    json={'query': '{__typename}'},
                    headers={**HEADERS, 'Content-Type': 'application/json'},
                    timeout=5
                )
                if resp.status_code in (200, 400):
                    introspection_enabled = False
                    try:
                        data = resp.json()
                        introspection_enabled = '__typename' in str(data) or 'data' in data
                    except Exception:
                        pass
                    endpoints.append({
                        'path': path,
                        'status': resp.status_code,
                        'introspection_enabled': introspection_enabled,
                    })
            except Exception:
                pass
        return {'graphql_endpoints': endpoints, 'success': True}

    def discover_swagger(self, domain: str) -> Dict[str, Any]:
        """Discover Swagger/OpenAPI documentation"""
        docs = []
        for path in self.SWAGGER_PATHS:
            try:
                resp = requests.get(
                    f"https://{domain}{path}", headers=HEADERS,
                    timeout=5, allow_redirects=True
                )
                if resp.status_code == 200:
                    content = resp.text.lower()
                    is_swagger = any(kw in content for kw in ['swagger', 'openapi', 'paths', 'definitions'])
                    if is_swagger:
                        docs.append({
                            'path': path,
                            'status': resp.status_code,
                            'content_type': resp.headers.get('Content-Type', ''),
                        })
            except Exception:
                pass
        return {'swagger_docs': docs, 'success': True}
