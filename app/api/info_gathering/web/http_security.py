from typing import Dict
import httpx


async def check_http_security(url: str) -> Dict:

    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(url)
            headers = response.headers
            
            return {
                'strict_transport_security': headers.get('strict-transport-security'),
                'x_frame_options': headers.get('x-frame-options'),
                'x_content_type_options': headers.get('x-content-type-options'),
                'x_xss_protection': headers.get('x-xss-protection'),
                'content_security_policy': headers.get('content-security-policy'),
                'referrer_policy': headers.get('referrer-policy'),
                'permissions_policy': headers.get('permissions-policy'),
                'server': headers.get('server'),
                'powered_by': headers.get('x-powered-by'),
            }
        except Exception as e:
            return {'error': str(e)}