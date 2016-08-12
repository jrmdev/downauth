import os
import sys
import config
import urlparse
import socket
import select
import ssl
import threading
import downgrade
import BaseHTTPServer

from base64 import b64decode
from SocketServer import TCPServer, ThreadingMixIn

class ProxySock:
	def __init__(self, socket, proxy_host, proxy_port) : 

		# First, use the socket, without any change
		self.socket = socket

		# Create socket (use real one)
		self.proxy_host = proxy_host
		self.proxy_port = proxy_port

		# Copy attributes
		self.family = socket.family
		self.type = socket.type


	def connect(self, address) :

		# Store the real remote adress
		(self.host, self.port) = address

		# Try to connect to the proxy 
		for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(
			self.proxy_host, 
			self.proxy_port,
			0, 0, socket.SOL_TCP) :
			try:
				
				# Replace the socket by a connection to the proxy
				self.socket = socket.socket(family, socktype, proto)
				self.socket.connect(sockaddr)
					
			except socket.error, msg:
				if self.socket:
					self.socket.close()
				self.socket = None
				continue
			break

		if not self.socket :
			raise socket.error, ms 
		
		# Ask him to create a tunnel connection to the target host/port
		self.socket.send(
				("CONNECT %s:%d HTTP/1.1\r\n" + 
				"Host: %s:%d\r\n\r\n") % (self.host, self.port, self.host, self.port))

		# Get the response
		resp = self.socket.recv(4096)

		# Parse the response
		parts = resp.split()

	# Wrap all methods of inner socket, without any change
	def accept(self) :
		return self.socket.accept()

	def bind(self, *args) :
		return self.socket.bind(*args)
	
	def close(self) :
		return self.socket.close()
	
	def fileno(self) :
		return self.socket.fileno()

	def getsockname(self) :
		return self.socket.getsockname()
	
	def getsockopt(self, *args) :
		return self.socket.getsockopt(*args)
	
	def listen(self, *args) :
		return self.socket.listen(*args)
	
	def makefile(self, *args) :
		return self.socket.makefile(*args)
	
	def recv(self, *args) :
		return self.socket.recv(*args)
	
	def recvfrom(self, *args) :
		return self.socket.recvfrom(*args)

	def recvfrom_into(self, *args) :
		return self.socket.recvfrom_into(*args)
	
	def recv_into(self, *args) :
		return self.socket.recv_into(buffer, *args)
	
	def send(self, *args) :
		try: return self.socket.send(*args)
		except: pass
	
	def sendall(self, *args) :
		return self.socket.sendall(*args)
	
	def sendto(self, *args) :
		return self.socket.sendto(*args)
	
	def setblocking(self, *args) :
		return self.socket.setblocking(*args)
	
	def settimeout(self, *args) :
		return self.socket.settimeout(*args)
	
	def gettimeout(self) :
		return self.socket.gettimeout()
	
	def setsockopt(self, *args):
		return self.socket.setsockopt(*args)
	
	def shutdown(self, *args):
		return self.socket.shutdown(*args)

	# Return the (host, port) of the actual target, not the proxy gateway
	def getpeername(self) :
		return self.host, self.port

class HTTP_Proxy(BaseHTTPServer.BaseHTTPRequestHandler):

	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle
	upstream = None
	rbufsize = 0

	def handle(self):
		(ip, port) =  self.client_address
		try:
			self.__base_handle()
		except ssl.SSLError:
			pass

	def log_message(self, format, *args):
		return

	def _connect_to(self, netloc, soc):

		i = netloc.find(':')
		host_port = (netloc[:i], int(netloc[i+1:])) if i>=0 else (netloc, 80)

		try:
			soc.connect(host_port)
		
		except socket.error, arg:
			self.send_error(404, 'Not Found')
			return 0
		
		return 1

	def do_CONNECT(self):

		if self.upstream is not None:
			soc = ProxySock(socket.socket(socket.AF_INET, socket.SOCK_STREAM), self.upstream[0], self.upstream[1])
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			if self._connect_to(self.path, soc):
				self.wfile.write(self.protocol_version +" 200 Connection established\r\n")
				self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
				self.wfile.write("\r\n")
				self._read_write(soc, 300)
		except Exception as e:
			print str(e)

		finally:
			soc.close()
			self.connection.close()

	def do_GET(self):

		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')

		if netloc == '':
			# Client is not proxy aware.
			# We have to operate in transparent proxy
			netloc = self.headers['Host']

		if scm not in 'http' or fragment or not netloc:
			self.send_error(400, "bad url %s" % self.path)
			return

		if self.upstream is not None:
			soc = ProxySock(socket.socket(socket.AF_INET, socket.SOCK_STREAM), self.upstream[0], self.upstream[1])
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		URL_Unparse = urlparse.urlunparse(('', '', path, params, query, ''))

		if self._connect_to(netloc, soc):
			soc.send("%s %s %s\r\n" % (self.command, URL_Unparse, self.request_version))

			self.headers['Connection'] = 'close'
			del self.headers['Proxy-Connection']
			del self.headers['If-Range']
			del self.headers['Range']

			if 'Authorization' in self.headers:
				self.headers = downgrade.decode_auth(self.headers, self.client_address, self.command, path)
			
			for k, v in self.headers.items():
				soc.send("%s: %s\r\n" % (k.title(), v))
			soc.send("\r\n")

			self._read_write(soc, netloc)

			soc.close()
			self.connection.close()

	def _read_write(self, soc, netloc='', max_idling=10):
		iw = [self.connection, soc]
		ow = []
		count = 0

		while 1:
			count += 1

			(ins, _, exs) = select.select(iw, ow, iw, 1)
			
			if exs:
				break

			if ins:
				for i in ins:
					if i is soc:
						out = self.connection

						data = i.recv(4096)
						sys.stdout.write(".")
						sys.stdout.flush()

						if len(data) > 1:
							data = downgrade.handle_server_response(self.headers, self.client_address, data)

					else:
						out = soc
						try:
							data = i.recv(4096)
					
							#if self.command == "POST":
							#	print "RECEIVED POSTDATA:", data

						except Exception as e:
							print str(e)

					if data: # forwarding server response to client
						out.send(data)
						count = 0

			if count == max_idling:
				break

		return None

	do_HEAD   = do_GET
	do_POST   = do_GET
	do_PUT    = do_GET
	do_DELETE = do_GET


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, cfg.args.local_ip+'\0')
		except:
			pass
		TCPServer.server_bind(self)

ThreadingTCPServer.allow_reuse_address = 1

class ProxyThread(threading.Thread):
	def __init__(self, ip, port):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.killed = False

	def run(self):
		HTTP_Proxy.server_version = 'Apache'
		HTTP_Proxy.sys_version = ''

		if config.cfg.args.proxy is not None:
			HTTP_Proxy.upstream = config.cfg.args.proxy

		self.server = ThreadingTCPServer((self.ip, self.port), HTTP_Proxy)
	
		if self.port == 443:
			from ssl import wrap_socket
			
			cert = os.path.join(os.path.dirname(__file__), 'cert', 'cert.crt')
			key =  os.path.join(os.path.dirname(__file__), 'cert', 'key.key')
			
			if not os.path.exists(cert) or not os.path.exists(key):
				print "Error: Certificate not found. Use the 'cert/gen-self-signed-cert.sh' script to use SSL interception."
				sys.exit()
			
			self.server.socket = wrap_socket(self.server.socket, certfile=cert, keyfile=key, server_side=True)
		
		self.server.serve_forever()
