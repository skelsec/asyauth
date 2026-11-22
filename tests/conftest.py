import os
import sys
import json
import time
import shutil
import asyncio
import subprocess

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MIT krb5 lab, see tests/lab/README.md
LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lab')
LAB_IMAGE = 'asyauth-krb5lab'
LAB_CONTAINER = 'asyauth-krb5lab'
LAB_REALM = 'TEST.LAB'
LAB_USER = 'alice'
LAB_PASSWORD = 'Passw0rd!'

def run(coro):
	return asyncio.run(coro)

def docker(*args, check = True, **kwargs):
	return subprocess.run(['docker'] + list(args), check = check, stdout = subprocess.PIPE, stderr = subprocess.PIPE, **kwargs)

class KRB5Lab:
	def __init__(self, ip):
		self.ip = ip
		self.realm = LAB_REALM
		self.user = LAB_USER
		self.password = LAB_PASSWORD

	def read_file(self, path):
		return docker('exec', LAB_CONTAINER, 'cat', path).stdout

	def get_peer(self):
		return MITPeer()

class MITPeer:
	"""MIT krb5 GSSAPI acceptor running in the lab container (tests/lab/peer.py)"""
	def __init__(self):
		self.proc = subprocess.Popen(['docker', 'exec', '-i', LAB_CONTAINER, 'python3', '-u', '/peer.py'], stdin = subprocess.PIPE, stdout = subprocess.PIPE)

	def call(self, **req):
		"""Returns the reply of the peer, raises if the peer reported an error"""
		res = self.call_raw(**req)
		if 'error' in res:
			raise Exception('MIT peer error: %s' % res['error'])
		return res

	def call_raw(self, **req):
		for k in req:
			if isinstance(req[k], bytes):
				req[k] = req[k].hex()
		self.proc.stdin.write(json.dumps(req).encode() + b'\n')
		self.proc.stdin.flush()
		line = self.proc.stdout.readline()
		if not line:
			raise Exception('MIT peer went away')
		return json.loads(line)

	def close(self):
		self.proc.stdin.close()
		self.proc.wait(timeout = 10)

@pytest.fixture(scope = 'session')
def lab():
	if shutil.which('docker') is None or docker('info', check = False).returncode != 0:
		pytest.skip('docker is not available')

	started = False
	res = docker('inspect', '-f', '{{.State.Running}}', LAB_CONTAINER, check = False)
	if res.returncode != 0 or res.stdout.strip() != b'true':
		docker('rm', '-f', LAB_CONTAINER, check = False)
		docker('build', '-q', '-t', LAB_IMAGE, LAB_DIR)
		docker('run', '-d', '--name', LAB_CONTAINER, '--hostname', 'kdc.test.lab', LAB_IMAGE)
		started = True

	for _ in range(60):
		if docker('exec', LAB_CONTAINER, 'test', '-e', '/ready', check = False).returncode == 0:
			break
		time.sleep(0.5)
	else:
		raise Exception('krb5 lab container did not come up')

	ip = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', LAB_CONTAINER).stdout.decode().strip()
	yield KRB5Lab(ip)

	if started is True and os.environ.get('ASYAUTH_LAB_KEEP') is None:
		docker('rm', '-f', LAB_CONTAINER, check = False)

@pytest.fixture
def peer(lab):
	p = lab.get_peer()
	yield p
	p.close()
