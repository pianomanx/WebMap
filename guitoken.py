#!/usr/bin/env python3

import string, hashlib, os
from random import *
allchar = string.ascii_letters + string.digits
password = "".join(choice(allchar) for x in range(randint(12, 12)))
print('Token generated and hashed.')
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
tokenhash = f"{salt.hex()}:{dk.hex()}"

with open('/root/token.sha256', 'w') as f:
	f.write(tokenhash)
