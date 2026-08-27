#!/usr/bin/env python3

import hashlib
import hmac
import os
import string
from random import choice

TOKEN_FILE = '/root/token.plain'
TOKEN_HASH_FILE = '/root/token.sha256'
TOKEN_LENGTH = 12
TOKEN_HASH_ITERATIONS = 600000


def generate_token(length=TOKEN_LENGTH):
	allchar = string.ascii_letters + string.digits
	return ''.join(choice(allchar) for _ in range(length))


def hash_token(token):
	salt = os.urandom(16)
	dk = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, TOKEN_HASH_ITERATIONS)
	return f"{salt.hex()}:{dk.hex()}"


def verify_token(token, stored_hash):
	if not token or not stored_hash:
		return False

	stored_hash = stored_hash.strip()
	if stored_hash == hashlib.sha256(token.encode('utf-8')).hexdigest():
		return True

	if ':' not in stored_hash:
		return False

	try:
		salt_hex, digest_hex = stored_hash.split(':', 1)
		salt = bytes.fromhex(salt_hex)
		expected = bytes.fromhex(digest_hex)
		actual = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, TOKEN_HASH_ITERATIONS)
		return hmac.compare_digest(actual, expected)
	except (TypeError, ValueError):
		return False


def write_token(token, token_file=None, token_hash_file=None):
	if token_file is None:
		token_file = TOKEN_FILE
	if token_hash_file is None:
		token_hash_file = TOKEN_HASH_FILE
	try:
		for path in (token_file, token_hash_file):
			parent_dir = os.path.dirname(path)
			if parent_dir:
				os.makedirs(parent_dir, exist_ok=True)

		with open(token_file, 'w') as f:
			f.write(token)
		with open(token_hash_file, 'w') as f:
			f.write(hash_token(token))
	except OSError:
		return token
	return token


def read_token(token_file=None):
	if token_file is None:
		token_file = TOKEN_FILE
	try:
		with open(token_file, 'r') as f:
			return f.read().strip()
	except OSError:
		return ''


def main():
	token = os.environ.get('WEBMAP_TOKEN')
	if not token:
		token = read_token()
	if not token:
		token = generate_token()
		write_token(token)
	print(token)
	return token


if __name__ == '__main__':
	main()
