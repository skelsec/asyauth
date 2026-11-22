import os
import sys
import json
import time
import shutil
import socket
import asyncio
import subprocess

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MIT krb5 lab, see tests/lab/README.md
LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lab')
LAB_IMAGE = 'asyauth-krb5lab'
LAB_USER = 'alice'
LAB_PASSWORD = 'Passw0rd!'
# realm -> (container, cross-realm krbtgt principals)
# TEST.LAB is trusted by OTHER.LAB which is trusted by THIRD.LAB
LAB_REALMS = {
	'TEST.LAB' : ('asyauth-krb5lab', 'krbtgt/OTHER.LAB@TEST.LAB'),
	'OTHER.LAB' : ('asyauth-krb5lab-other', 'krbtgt/OTHER.LAB@TEST.LAB krbtgt/THIRD.LAB@OTHER.LAB'),
	'THIRD.LAB' : ('asyauth-krb5lab-third', 'krbtgt/THIRD.LAB@OTHER.LAB'),
}

def run(coro):
	return asyncio.run(coro)

def docker(*args, check = True, **kwargs):
	return subprocess.run(['docker'] + list(args), check = check, stdout = subprocess.PIPE, stderr = subprocess.PIPE, **kwargs)

class KRB5Lab:
	"""One realm of the lab: KDC and MIT GSSAPI acceptor in a container"""
	def __init__(self, realm):
		self.realm = realm
		self.domain = realm.lower()
		self.container, self.trusts = LAB_REALMS[realm]
		self.user = LAB_USER
		self.password = LAB_PASSWORD
		self.ip = None
		self.started = False

	def is_running(self):
		res = docker('inspect', '-f', '{{.State.Running}}', self.container, check = False)
		return res.returncode == 0 and res.stdout.strip() == b'true'

	def start(self):
		if self.is_running() is False:
			docker('rm', '-f', self.container, check = False)
			docker('run', '-d', '--name', self.container, '--hostname', 'kdc.%s' % self.domain, '-e', 'LAB_REALM=%s' % self.realm, '-e', 'LAB_TRUSTS=%s' % self.trusts, LAB_IMAGE)
			self.started = True

	def wait(self):
		for _ in range(60):
			if docker('exec', self.container, 'test', '-e', '/ready', check = False).returncode == 0:
				break
			time.sleep(0.5)
		else:
			raise Exception('krb5 lab container %s did not come up' % self.container)
		self.ip = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', self.container).stdout.decode().strip()

	def stop(self):
		if self.started is True and os.environ.get('ASYAUTH_LAB_KEEP') is None:
			docker('rm', '-f', self.container, check = False)

	def read_file(self, path):
		return docker('exec', self.container, 'cat', path).stdout

	def run(self, script, env = {}):
		"""Runs a shell script in the container"""
		args = ['exec', '-i']
		for k in env:
			args += ['-e', '%s=%s' % (k, env[k])]
		return docker(*args, self.container, 'sh', '-e', input = script.encode()).stdout

	def get_peer(self):
		return MITPeer(self.container)

class MITPeer:
	"""MIT krb5 GSSAPI acceptor running in the lab container (tests/lab/peer.py)"""
	def __init__(self, container):
		self.proc = subprocess.Popen(['docker', 'exec', '-i', container, 'python3', '-u', '/peer.py'], stdin = subprocess.PIPE, stdout = subprocess.PIPE)

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

def start_labs(realms):
	if shutil.which('docker') is None or docker('info', check = False).returncode != 0:
		pytest.skip('docker is not available')
	labs = [KRB5Lab(realm) for realm in realms]
	if any(lab.is_running() is False for lab in labs):
		docker('build', '-q', '-t', LAB_IMAGE, LAB_DIR)
	for lab in labs:
		lab.start()
	for lab in labs:
		lab.wait()
	return labs

@pytest.fixture(scope = 'session')
def lab():
	labs = start_labs(['TEST.LAB'])
	yield labs[0]
	labs[0].stop()

@pytest.fixture(scope = 'session')
def xlabs(lab):
	"""The other realms of the lab for the cross-realm tests, by name. Includes the home realm."""
	labs = start_labs(['OTHER.LAB', 'THIRD.LAB'])
	yield {x.realm : x for x in [lab] + labs}
	for x in labs:
		x.stop()

@pytest.fixture
def peer(lab):
	p = lab.get_peer()
	yield p
	p.close()

@pytest.fixture
def realm_dns(xlabs, monkeypatch):
	"""Makes the names of the lab realms resolve to their KDC, like in an AD environment"""
	getaddrinfo = socket.getaddrinfo
	def lab_getaddrinfo(host, *args, **kwargs):
		if isinstance(host, str) and host.upper() in xlabs:
			host = xlabs[host.upper()].ip
		return getaddrinfo(host, *args, **kwargs)
	monkeypatch.setattr(socket, 'getaddrinfo', lab_getaddrinfo)
