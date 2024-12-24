import aiohttp

import urllib.parse
import logging
import os
import base64
import hashlib
from jose import jwt

from jose import jwk, jwt

_LOGGER = logging.getLogger(__name__)

class OIDCClient:
    flows = {}

    def __init__(self, discovery_url, client_id, scope):
        self.discovery_url = discovery_url
        self.client_id = client_id
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
    
    async def get_authorization_url(self, base_uri):
        if not hasattr(self, 'discovery_document'):
            self.discovery_document = await self.fetch_discovery_document()

        if not self.discovery_document:
            return None

        auth_endpoint = self.discovery_document['authorization_endpoint']

        # Generate the necessary PKCE parameters, nonce & state
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).rstrip(b'=').decode('utf-8')
        nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b'=').decode('utf-8')
        state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b'=').decode('utf-8')

        # Save all of them for later verification
        self.flows[state] = {
            'code_verifier': code_verifier,
            'nonce': nonce
        }

        # Construct the params
        query_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': base_uri + '/auth/oidc/callback',
            'scope': self.scope,
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        url = f"{auth_endpoint}?{urllib.parse.urlencode(query_params)}"
        return url
    
    async def _make_token_request(self, token_endpoint, query_params):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(token_endpoint, data=query_params) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            response_json = await response.json()
            _LOGGER.warning(f"Error: {e.status} - {e.message}, Response: {response_json}")
            return None

        return None
    
    async def _get_jwks(self, jwks_uri):
        """Fetches JWKS from the given URL."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_uri) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            _LOGGER.warning(f"Error fetching JWKS: {e.status} - {e.message}")
            return None

    async def _parse_id_token(self, id_token):
        # Parse the id token to obtain the relevant details
        # Use python-jose
        if not hasattr(self, 'discovery_document'):
            self.discovery_document = await self.fetch_discovery_document()

        if not self.discovery_document:
            return None
        
        jwks_uri = self.discovery_document['jwks_uri']

        jwks_data = await self._get_jwks(jwks_uri)
        if not jwks_data:
            return None

        try:
            unverified_header = jwt.get_unverified_header(id_token)
            if not unverified_header:
                print("Could not parse JWT Header")
                return None

            kid = unverified_header.get('kid')
            if not kid:
                print("JWT does not have kid (Key ID)")
                return None


            # Get the correct key
            rsa_key = None
            for key in jwks_data["keys"]:
                if key["kid"] == kid:
                    rsa_key = key
                    break

            if not rsa_key:
                print(f"Could not find matching key with kid:{kid}")
                return None

            # Construct the JWK
            jwk_obj = jwk.construct(rsa_key)

            # Verify the token
            decoded_token = jwt.decode(
                id_token,
                jwk_obj,
                algorithms=["RS256"],  # Adjust if your algorithm is different
                audience=self.client_id,
                issuer=self.discovery_document['issuer'],
            )
            return decoded_token

        except jwt.JWTError as e:
            print(f"JWT Verification failed: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
    
        return None
    
    async def complete_token_flow(self, base_uri, code, state):
        if state not in self.flows:
            return None

        flow = self.flows[state]
        code_verifier = flow['code_verifier']

        if not hasattr(self, 'discovery_document'):
            self.discovery_document = await self.fetch_discovery_document()

        if not self.discovery_document:
            return None

        token_endpoint = self.discovery_document['token_endpoint']

        # Construct the params
        query_params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': base_uri + '/auth/oidc/callback',
            'code_verifier': code_verifier,
        }

        _LOGGER.debug(f"Token request params: {query_params}")

        token_response = await self._make_token_request(token_endpoint, query_params)

        if not token_response:
            return None

        access_token = token_response.get('access_token')
        id_token = token_response.get('id_token')
        _LOGGER.debug(f"Access Token: {access_token}")
        _LOGGER.debug(f"ID Token: {id_token}")

        # Parse the id token to obtain the relevant details
        id_token = await self._parse_id_token(id_token)

        # Verify nonce
        if id_token.get('nonce') != flow['nonce']:
            _LOGGER.warning(f"Nonce mismatch!")
            return None
        
        return {
            "name": id_token.get("name"),
            "email": id_token.get("email"),
            "preferred_username": id_token.get("preferred_username"),
            "nickname": id_token.get("nickname"),
            "groups": id_token.get("groups"),
        }