# Downauth
Downauth is a script that downgrades authentication requests from servers in order to capture clear-text credentials from target clients.

### Why "downauth" ?
Because finding names for software is hard.

### What does it do

This tool is a man-in-the-middle utility intended to downgrade authentication requests it receives 
to Basic in order to capture clear-text credentials.  This is done by:

- ARP cache poisoning the target(s) to redirect their traffic to the attacker ;
- Starting a local HTTP proxy instance ;
- Redirecting the targets' connections to the specified ports to the local proxy ;
- Relaying HTTP/S traffic to and from clients ;
- Intercepting NTLM, Negotiate and Digest auth. requests from the remote web servers or proxy ;
- Rewriting the responses to request Basic authentication.

HTTPS will be intercepted if port 443 is specified, however clients may see certificate warnings.

When the program receives Basic credentials, it will rewrite the auth to the format initially 
requested by the server.  At the moment, this is supported for Digest auth only (TODO: NTLM / Negotiate)

Levels of attakcs from stealthiest to noisiest (different levels can be used simultaneously):

1. Downgrade authentication requests in 407 responses (most likely domain accounts)
2. Downgrade authentication requests in 401 responses (for web apps / intranets / ...)
TODO: 3. Rewrite 200 responses to 401 to force authentication (very intrusive)

By default the tool will stop all attacks towards any given client after clear-text credentials have
been captured from this client.  To continue attacking no matter what, this can be disabled with the 
--nonstop option (very intrusive++).

### Getting started

Example usage:

	sudo python downauth.py --iface eth0 --levels 1,2 192.168.1.0/24

Options:

	positional arguments:
	  <target>           Comma-sparated list of target IP addresses or CIDR networks

	optional arguments:
	  -h, --help         show this help message and exit
	  --router <router>  Local network gateway (default: autodetect)
	  --iface <iface>    Network interface card to use (default: eth0)
	  --nofw             Do not auto-configure routing and iptables rules (default: false)
	  --freq <freq>      ARP poison packets frequency in seconds (default: 5)
	  --ports <ports>    Comma seperated list of ports to intercept (default: 80)
	  --proxy <proxy>    External proxy to forward clients' traffic to (format: ip:port)
	                     
	  --nonstop          Continue attacking clients after capturing credentials (default: false) 
	  --levels <levels>  Comma separated list of attack levels. See above for description (default: 1)
	                     
	  --verbose          Enable verbose output


### Todo

- Implement attack level 3
- Rewrite client auth response to NTLM or Negociate when required.