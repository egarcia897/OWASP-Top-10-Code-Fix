"""#09 Server-Side Request Forgery
- Secure code python"""

import requests
from urllib.parse import  urlparse

ALLOWED_DOMAINS = ['api.example.com', 'trusted-service.com']

def is_safe_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ['http', 'https']:
            return False
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
        
        return True
    except:
        return False
url = input("Enter URL: ")

if not is_safe_url(url):
    print("Error: URL not allowed")
else:
    response = requests.get(url, timeout=5, allow_redirects=False)
    print(response.text)