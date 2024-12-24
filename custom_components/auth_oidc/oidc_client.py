import aiohttp

import urllib.parse
import logging

_LOGGER = logging.getLogger(__name__)

class OIDCClient:
    def __init__(self, discovery_url, client_id, redirect_uri, scope):
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope

    async def fetch_discovery_document(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.discovery_url) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                _LOGGER.warning(f"Error: Discovery document not found at {self.discovery_url}")
            else:
                _LOGGER.warning(f"Error: {e.status} - {e.message}")
            return None
    
    async def get_authorization_url(self):
        if not hasattr(self, 'discovery_document'):
            self.discovery_document = await self.fetch_discovery_document()

        if not self.discovery_document:
            return None

        auth_endpoint = self.discovery_document['authorization_endpoint']
        
        query_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope
        }
        
        url = f"{auth_endpoint}?{urllib.parse.urlencode(query_params)}"
        return url