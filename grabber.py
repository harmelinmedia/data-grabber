
import os, sys, json, logging
import requests
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from base64 import b64encode, b64decode

class GrabberError(Exception):
	pass

class GrabberAuthError(GrabberError):
	pass

class GrabberAuthInvalidCredentials(GrabberAuthError):
	pass

class GrabberAuthExpiredCredentials(GrabberAuthError):
	pass

class GrabberAuthBadAuthFile(GrabberAuthError):
	pass

class GrabberInitError(GrabberError):
	pass

class GrabberInitUrlParseError(GrabberInitError):
	pass

class GrabberInitKeyError(GrabberError, KeyError):
	pass

class GrabberInitFileError(GrabberError, OSError):
	pass


class Grabber(object):

	"""
	.conf file format.

	{
		"name": "some-name-for-tmpfile-naming-scheme",
		"files": {
			"tmp_dir": "/path/to/tmp/dir/",
			"auth_dir": "/path/to/file"
		},
		"endpoints": {
			"auth": "https://host.domain.url/auth/",
			"base": "https://host.domain.url/endpoint/",
			"test_auth": "$BASE/200endpoint/"
		}
	}

	"""

	_default_datetime_fmt = '%Y%m%d%H%M%S'
	_required_conf_keys = ['name','files','endpoints']
	_required_files = ['tmp','auth_data','auth_credentials']
	_required_endpoints = ['auth','base','test_auth']

	def __init__(self, conf):

		logging.debug('Initializing Grabber')

		# load conf file
		self._parse_conf(conf)

		# parse endpoint definitions
		self._parse_endpoints()

		# create directories from config file
		self._check_for_directories

		# define Grabber session
		self.session_refresh()

	### universal methods that can be sublclassed without changing

	def _parse_conf(self, conf):
		with open(conf, 'r') as conf:
			conf = json.load(conf)

		# check conf file compliance
		for key in self._required_conf_keys:
			if key not in conf:
				raise GrabberInitKeyError( "Key Missing: %s\nConfiguration file \"%s\" must contain valid JSON with the following keys defined: [%s]" % (key, conf, ', '.join(self._required_conf_keys) ) )

		# ensure that default minimum endpoints are defined
		for key in self._required_files:
			if key not in conf['files']:
				raise GrabberInitKeyError( "Key Missing: %s\nConfiguration file \"%s\" must contain valid JSON with the following file paths defined: [%s]" % (key, conf, ', '.join(self._required_endpoints) ) )
		
		# ensure that default minimum endpoints are defined
		for key in self._required_endpoints:
			if key not in conf['endpoints']:
				raise GrabberInitKeyError( "Key Missing: %s\nConfiguration file \"%s\" must contain valid JSON with the following endpoints defined: [%s]" % (key, conf, ', '.join(self._required_endpoints) ) )

		# assign conf values to Grabber object
		for k, v in conf.items():
			if k == "auth_credentials":
				self.auth_credentials = self.parse_credentials(v)
			elif k != "auth_credentials" and type(v) == str:
				exec( "self.%s = \"%s\"" % (str(k), str(v)) )
			else:
				exec( "self.%s = %s" % (str(k), str(v)) )

	def _parse_endpoints(self):
		logging.debug('Parsing endpoints')


		key_queue = [key for key, val in self.endpoints.items() if val[0] == '$']

		while 1: # repeat process until Error or finishing condition
			aliases = { '$'+k.upper(): v for k, v in self.endpoints.items() }
			retry_queue = []
			for key in key_queue:
				val = self.endpoints[key]
				val_split = val.split('/')
				try:
					root = aliases[ val_split[0] ]
					if root[0] == '$':
						retry_queue.append(key)
					else:
						self.endpoints[key] = os.path.join( root, *val_split[1:] )
				except KeyError:
					raise GrabberInitUrlParseError("Endpoint alias %s not found. Please check endpoint configurations in .conf file." % val_split[0] )
			if set(key_queue) == set(retry_queue):
				raise GrabberInitUrlParseError("Endpoint alias %s not found. Please check endpoint configurations in .conf file. Look for infinite loop in URL definitions." % val_split[0] )
			if len(retry_queue) <= 0:
				break
			else:
				key_queue = retry_queue

	def _check_for_directories(self):
		logging.debug('Checking for directories')

		for key, val in self.files.items():
			if not os.path.exists(val):
				logging.debug("Creating directory: %s" % val)
				os.makedirs(val)


	def session_refresh(self):
		logging.debug('Starting new session')
		self.session = requests.Session()

	def timestamp(self, fmt=_default_datetime_fmt):
		"""outputs current datetime. if `fmt` is provided as string, output is string. if `fmt` is None, output is datetime object"""
		if fmt is None:
			return datetime.now()
		return datetime.now().strftime(fmt)

	def send(self, ro):
		logging.info('Sending request')
		ro = self.authenticate_request(ro)
		return self.session.send(ro.prepare())

	def authenticate(self):
		logging.debug('Authenticating...')
		test = self.test_auth()
		if not test:
			self.refresh_auth_data()
			test = self.test_auth()
		return test

	def test_auth(self, *urlargs):
		logging.debug('Testing authentication...',)
		ro = requests.Request(
					method = 'GET',
					url = self.fill_url( self.endpoints['test_auth'], *urlargs)
					)
		resp = self.send(ro)
		if resp.status_code == requests.codes.ok:
			return True
		else:
			logging.debug(resp.text)
			return False

	def fill_url(self, url, *args):
		return url % args

	def download_to_tmp(self, ro, fname, ext='.csv'): # METHOD NEEDS FIXES TO MATCH THIS CLASS
		"""takes streaming request object and saves to temporary file"""

		logging.info('Saving temp file')

		filepath = os.path.join( self.tmp,'_'.join([ 'tmpdata',self.name, fname, self.timestamp() ]) + ext )

		with open( filepath, 'wb' ) as fout:
			for chunk in ro.iter_content(chunk_size=1024**2): #1 mb per chunk
				if chunk:
					fout.write(chunk)
					fout.flush()
		return filepath

	### class specific methods
	def save_auth_to_file(self, text):
		with open(self.auth_data, 'w') as af:
			af.write(text)

	def load_auth_from_file(self):
		if os.path.isfile(self.auth_data):
			try:
				return self.parse_auth_data()
			except GrabberAuthBadAuthFile:
				self.refresh_auth_data() 
				return self.parse_auth_data()
		else:
			self.refresh_auth_data()
			return self.parse_auth_data()

	def parse_credentials(self):
		"""returns API credentials as dictionary"""
		raise NotImplementedError
	
	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		raise NotImplementedError

	def parse_auth_data(self, auth_fp):
		"""Parses auth file, raises Exception if not successful"""
		raise NotImplementedError

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		raise NotImplementedError

	def run_download_jobs(self):
		raise NotImplementedError

	def run_parse_jobs(self):
		raise NotImplementedError		


class TubeMogulGrabber(Grabber):

	def parse_credentials(self):
		"""returns API credentials as dictionary"""
		raise NotImplementedError
	
	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		raise NotImplementedError

	def parse_auth_data(self, auth_fp):
		"""Parses auth file, raises Exception if not successful"""
		raise NotImplementedError

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		raise NotImplementedError	


class MediaMathGrabber(Grabber): 

	def parse_credentials(self, path):
		with open(path, 'r') as creds:
			return json.load(creds)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		auth = self.load_auth_from_file()
		ro.cookies = auth
		return ro

	def parse_auth_data(self):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		with open(self.auth_data, 'r') as cookie:
			cookie_soup = BeautifulSoup(cookie.read(), "html.parser")
			if datetime.strptime(cookie_soup.result.session['expires'], "%Y-%m-%dT%H:%M:%S") - datetime.utcnow() > timedelta(hours=1):
				return {'adama_session': cookie_soup.result.session['sessionid']}
			raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		print("Renewing authorization")
		response = self.session.post( self.endpoints['auth'], data=self.auth_credentials)
		if response.status_code == requests.codes.ok:
			self.save_auth_to_file(response.text)
		else:
			raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


class GoogleGrabber(Grabber):

	def test_auth(self, *urlargs ):
		return super().test_auth(self.profile_id, *urlargs)

	def parse_credentials(self, path):
		with open(path, 'r') as creds:
			return json.load(creds)['installed']

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = {"Authorization": "Bearer " + token}
		return ro

	def parse_auth_data(self):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		with open(self.auth_data, 'r') as auth_data:
			auth = json.load(auth_data)
			if datetime.strptime(auth['expires_at'], "%Y%m%d%H%M%S") - datetime.utcnow() > timedelta(minutes=10):
				return auth['access_token']
			raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		print("Renewing authorization")

		cr = self.auth_credentials

		try:
			with open(self.auth_refresh, 'r') as tk:
				auth = json.load(tk)
		except Exception:
			auth = {}

		if 'refresh_token' in auth:
			data = {
				'client_id' : cr['client_id'],
				'client_secret' : cr['client_secret'],
				'refresh_token' : auth['refresh_token'],
				'grant_type' : 'refresh_token',
				'redirect_uri' : cr['redirect_uris'][0]
			}
			response = self.session.post( self.endpoints['auth_token'], data=data )
			if response.status_code == requests.codes.ok:
				response_data = json.loads(response.text)
				response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
				with open(self.auth_data, 'w') as out:
					json.dump(response_data, out)
			else:
				raise GrabberAuthInvalidCredentials('Token invalid. Authorization not granted.')

		else:

			params = {
				'scope': ['https://www.googleapis.com/auth/dfareporting','https://www.googleapis.com/auth/analytics.readonly'],
				'redirect_uri': cr['redirect_uris'][0],
				'response_type': 'code',
				'client_id': cr['client_id']
			}

			ro = requests.Request( url=self.endpoints['auth_access'], params=params )

			print("\nGo to this url to authenticate app:\n\n%s\n" % ro.prepare().url)

			auth_code = input("Paste code here: ")

			data = {
				'client_id' : cr['client_id'],
				'client_secret' : cr['client_secret'],
				'code': auth_code,
				'grant_type' : 'authorization_code',
				'redirect_uri' : cr['redirect_uris'][0]
			}

			response = self.session.post( self.endpoints['auth_token'], data=data )
			if response.status_code == requests.codes.ok:
				response_data = json.loads(response.text)
				response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
				with open(self.auth_data, 'w') as out:
					json.dump(response_data, out)
				with open(self.auth_refresh, 'w') as out:
					json.dump(response_data, out)
			else:
				raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


class PointrollGrabber(Grabber):

	def parse_credentials(self):
		"""returns API credentials as dictionary"""
		raise NotImplementedError
	
	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		raise NotImplementedError

	def parse_auth_data(self, auth_fp):
		"""Parses auth file, raises Exception if not successful"""
		raise NotImplementedError

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		raise NotImplementedError

if __name__=="__main__":

	logging.basicConfig(stream=sys.stdout, level=logging.DEBUG) ## for local debugging

	mma = MediaMathGrabber('mediamath/mm.conf')
	# print(mma.endpoints)
	print("Auth", mma.authenticate())

	# dcm = DCMGrabber('dcm.conf')

	# print( dcm.fill_url("/auth/dfareporting/v2.2/userprofiles/%s/accounts", dcm.profile_id))

	# print(mma.endpoints)
	# print("Auth", dcm.test_auth())

	parameters = {'filter':'agency_id=100480',
		'dimensions':'campaign_name,tpas_placement_name,strategy_name',
		'start_date':'2014-01-01',
		'end_date':'2015-09-30',
		'time_rollup':'by_month',
		'metrics':'impressions,margin,adserving_cost,adverification_cost,privacy_compliance_cost,contextual_cost,dynamic_creative_cost,media_cost,optimization_fee,pmp_no_opto_fee,pmp_opto_fee,platform_access_fee,mm_data_cost,mm_total_fee,total_ad_cost,billed_spend,total_spend'}

	# mma.authenticate()

	# print(mma.endpoints['performance'])

	# ro = requests.Request( method='get', url=mma.endpoints['meta'], params=parameters)

	# ro = mma.authenticate_request(ro)

	# mma.session.stream=True

	# resp = mma.send(ro)

	# # mma.download_to_tmp(resp, 'mm-performance-metadata')
	# # print("Done")

	# from pprint import pprint as pp
	# pp(resp.text)

	# print("Auth:", mma.has_auth())

	


