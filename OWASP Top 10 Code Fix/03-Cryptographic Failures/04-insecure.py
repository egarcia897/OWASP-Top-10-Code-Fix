""" # 04 Cryptographic Failures
- Insecure code Python"""

import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()