class Config:
	init_ipfwd = None
	init_redir = None
	args = None
	my = ()
	router = ()

def init():
	global cfg
	cfg = Config()
