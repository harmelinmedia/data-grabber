#!/usr/local/bin/python3

# base imports
import os, sys, json, logging
from datetime import datetime, timedelta
from base64 import b64encode, b64decode

# third-party library imports
import requests
from bs4 import BeautifulSoup

# local imports
from errors import *

# Conf objects
class Conf(object):

	"""Conf objects make config file definitions available like so:

	{
		"name":"some-name",
		"urls": {
			"url1":"http://some.url",
			"url2":"http://some_other.url"
		}
		...etc...
	}

	These can be accessed as attributes.

	$ print(self.name)
	some-name

	$ print(self.urls.url1)
	"http://some.url"

	"""

	_required_keys = []
	_init_keyerror_string = "Keys Missing: [%s] Configuration file must contain valid JSON with the following key defined: [%s]"

	def __init__(self, data):
		print(self._required_keys)
		self.check_requirements(data)

	def check_requirements(self, data):
		missing_keys = []
		for key in self._required_keys:
			if key not in data:
				missing_keys.append(key)
		if len(missing_keys) > 0:
			raise ConfInitKeyError( self._init_keyerror_string % ( ', '.join(missing_keys), ', '.join(self._required_keys) ) )

	def dict_to_attr(self, data):
		# assign conf values to Grabber object
		for k, v in data.items():
			if type(v) == str:
				exec( "self.%s = \"%s\"" % (str(k), str(v)) )
			else:
				exec( "self.%s = %s" % (str(k), str(v)) )

class FileConf(Conf):
	_required_keys = ['tmp','auth']
	_init_keyerror_string = "Keys Missing: [%s] Configuration file `files` must contain valid JSON with the following key defined: [%s]"

	def __init__(self, data):
		super().__init__(data)
		self.check_for_directories(data)
		self.dict_to_attr(data)

	def check_for_directories(self, data):
		logging.debug('Checking for directories')

		for key, val in data.items():
			if not os.path.exists(val):
				logging.debug("Creating directory: %s" % val)
				os.makedirs(val)

class URLConf(Conf):
	_required_keys = ['auth','base','test']
	_init_keyerror_string = "Keys Missing: [%s] Configuration file `urls` must contain valid JSON with the following key defined: [%s]"

	def __init__(self, data):
		super().__init__(data)
		self.dict_to_attr( self.parse_urls(data) )

	def parse_urls(self, data):
		logging.debug('Parsing urls')
		key_queue = [key for key, val in data.items() if val[0] == '$']
		# takes URL defined with $ALIAS and fills out urls
		while 1: # repeat process until Error or finishing condition
			aliases = { '$'+k.upper(): v for k, v in data.items() }
			retry_queue = []
			for key in key_queue:
				val = data[key]
				val_split = val.split('/')
				try:
					root = aliases[ val_split[0] ]
					if root[0] == '$': 
						retry_queue.append(key)
					else:
						data[key] = os.path.join( root, *val_split[1:] )
				except KeyError:
					raise GrabberInitUrlParseError("url alias %s not found. Please check url configurations in `conf` file." % val_split[0] )
			if set(key_queue) == set(retry_queue):
				raise GrabberInitUrlParseError("url alias %s not found. Please check url configurations in `conf` file. Look for self-referential loop in aliased URL definitions." % val_split[0] )
			if len(retry_queue) <= 0:
				break
			else:
				key_queue = retry_queue
		return data


# MAIN CLASS
class Grabber(object):

	"""
	`conf` file format. Must be valid JSON.

	{
		"name": "some-api-name",
		"files": {
			"tmp": "/path/to/tmp/dir/",
			"auth": "/path/to/file"
		},
		"urls": {
			"auth": "https://host.domain.url/auth/",
			"base": "https://host.domain.url/url/",
			"test_auth": "$BASE/200url/"
		}
	}

	"""

	_required_keys = ['name','files','urls']
	_default_datetime_fmt = '%Y%m%d%H%M%S'

	def __init__(self, conf):
		logging.debug('Initializing Grabber')
		self._parse_conf(conf) # load conf file
		self.credentials_file = self.cpath("credentials")
		self.token_file = self.cpath("token")
		self.refresh_file = self.cpath("refresh")
		self.credentials = self.parse_credentials() # set credentials
		self.session_refresh() # create Grabber session

	### class methods
	def _parse_conf(self, path):
		try:
			with open(path, 'r') as conf:
				conf = json.load(conf)
		except Exception:
			raise GrabberInitFileError("Bad config file could not be read or parsed. Check to ensure file exists and contains valid JSON.\nPath: %s" % path)

		# check conf file compliance
		missing_keys = []
		for key in self._required_keys:
			if key not in data:
				missing_keys.append(key)
		if len(missing_keys) > 0:
			raise GrabberInitKeyError( "Key Missing: %s Configuration file \"%s\" must contain valid JSON with the following keys defined: [%s]" % (', '.join(missing_keys), path, ', '.join(self._required_keys) ) )

		self.files = FileConf( conf["files"] )
		self.urls = URLConf( conf["urls"] )
		self.dict_to_attr(conf)

	def dict_to_attr(self, data):
		# assign conf values to Grabber object attributes
		for k, v in data.items():
			if k not in ["files", "urls"]:
				if type(v) == str:
					exec( "self.%s = \"%s\"" % (str(k), str(v)) )
				else:
					exec( "self.%s = %s" % (str(k), str(v)) )

	def cpath(self, cname):
		"""helper method for defining full file paths for authentication files"""
		return os.path.join( self.files.auth, cname)

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

	def fill_url(self, url, *args):
		return url % args

	def test_auth(self, *urlargs):
		logging.debug('Testing authentication...',)
		ro = requests.Request(
					method = 'GET',
					url = self.fill_url( self.urls.test, *urlargs)
					)
		resp = self.send(ro)
		if resp.status_code == requests.codes.ok:
			return True
		else:
			logging.debug(resp.text)
			return False

	def download_to_tmp(self, ro, fname, ext='.csv'): # METHOD NEEDS FIXES TO MATCH THIS CLASS
		"""takes streaming request object and saves to temporary file"""

		logging.info('Saving temp file')

		filepath = os.path.join( self.files.tmp, '_'.join([ 'tmpdata',self.name, fname, self.timestamp() ]) + ext )

		with open( filepath, 'wb' ) as fout:
			for chunk in ro.iter_content(chunk_size=1024**2): #1 mb per chunk
				if chunk:
					fout.write(chunk)
					fout.flush()
		return filepath

	### subclass methods
	def save_auth_to_file(self, text):
		with open(self.token_file, 'w') as af:
			af.write(text)

	def load_auth_from_file(self):
		if os.path.isfile(self.token_file):
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

	# these might be defined in a scheduler class... not sure yet. Not used for now.
	# def run_download_jobs(self):
	# 	raise NotImplementedError

	# def run_parse_jobs(self):
	# 	raise NotImplementedError

class TubeMogulGrabber(Grabber):

	def parse_credentials(self):
		with open(self.credentials_file, 'r') as cr:
			return json.load(cr)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = {"Authorization": "Bearer " + token}
		return ro

	def parse_auth_data(self):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		with open(self.token_file, 'r') as tk:
			auth = json.load(tk)
			if datetime.strptime(auth['expires_at'], "%Y%m%d%H%M%S") - datetime.utcnow() > timedelta(minutes=10):
				return auth['token']
			raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		logging.debug("Renewing authorization")

		clid, sk = self.credentials["client_id"], self.credentials["secret_key"]
		params={"grant_type":"client_credentials"}

		header = {"Cache-Control":"no-cache",
			"Content-Type":"application/x-www-form-urlencoded",
			"Authorization":"Basic " + b64encode(str(clid+":"+sk).encode('utf8')).decode('ascii')}

		response = self.session.post( self.urls.auth, headers=header, params=params)

		if response.status_code == requests.codes.ok:
			response_data = json.loads(response.text)
			response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
			with open(self.token_file, 'w') as out:
				json.dump(response_data, out)
		else:
			logging.debug(header)
			logging.debug(response.text)
			raise GrabberAuthInvalidCredentials('Token invalid. Authorization not granted.')


class MediaMathGrabber(Grabber):

	def parse_credentials(self):
		with open(self.credentials_file, 'r') as cr:
			return json.load(cr)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		auth = self.load_auth_from_file()
		ro.cookies = auth
		return ro

	def parse_auth_data(self):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		with open(self.token_file, 'r') as cookie:
			cookie_soup = BeautifulSoup(cookie.read(), "html.parser")
			if datetime.strptime(cookie_soup.result.session['expires'], "%Y-%m-%dT%H:%M:%S") - datetime.utcnow() > timedelta(hours=1):
				return {'adama_session': cookie_soup.result.session['sessionid']}
			raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		logging.debug("Renewing authorization")
		response = self.session.post( self.urls.auth, data=self.credentials)
		if response.status_code == requests.codes.ok:
			self.save_auth_to_file(response.text)
		else:
			raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


class GoogleGrabber(Grabber):

	def __init__(self, conf):
		super().__init__(conf)

	def test_auth(self, *urlargs ):
		return super().test_auth(self.profile_id, *urlargs)

	def parse_credentials(self):
		with open(self.credentials_file, 'r') as cr:
			return json.load(cr)['installed']

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = {"Authorization": "Bearer " + token}
		return ro

	def parse_auth_data(self):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		with open(self.token_file, 'r') as tk:
			auth = json.load(tk)
			if datetime.strptime(auth['expires_at'], "%Y%m%d%H%M%S") - datetime.utcnow() > timedelta(minutes=10):
				return auth['access_token']
			raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		logging.debug("Renewing authorization")

		cr = self.credentials

		try:
			with open(self.refresh_file, 'r') as tk:
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
			response = self.session.post( self.urls.auth_token, data=data )
			if response.status_code == requests.codes.ok:
				response_data = json.loads(response.text)
				response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
				with open(self.token_file, 'w') as out:
					json.dump(response_data, out)
			else:
				raise GrabberAuthInvalidCredentials('Token invalid. Authorization not granted.')

		else:

			params = {
				'scope': self.scope,
				'redirect_uri': cr['redirect_uris'][0],
				'response_type': 'code',
				'client_id': cr['client_id']
			}

			ro = requests.Request( url=self.urls.auth_access, params=params )

			print("\nGo to this url to authenticate app:\n\n%s\n" % ro.prepare().url)

			auth_code = input("Paste code here: ")

			data = {
				'client_id' : cr['client_id'],
				'client_secret' : cr['client_secret'],
				'code': auth_code,
				'grant_type' : 'authorization_code',
				'redirect_uri' : cr['redirect_uris'][0]
			}

			response = self.session.post( self.urls.auth_token, data=data )
			if response.status_code == requests.codes.ok:
				response_data = json.loads(response.text)
				response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
				with open(self.token_file, 'w') as out:
					json.dump(response_data, out)
				with open(self.refresh_file, 'w') as out:
					json.dump(response_data, out)
			else:
				raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')

class DFAGrabber(GoogleGrabber):

	def __init__(self, conf):
		super().__init__(conf)
		self.scope = ['https://www.googleapis.com/auth/dfareporting']

class GoogleAnalyticsGrabber(GoogleGrabber):

	def __init__(self, conf):
		super().__init__(conf)
		self.scope = ['https://www.googleapis.com/auth/analytics.readonly']

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

	# mma = MediaMathGrabber("mediamath/conf")
	# print(mma.urls)
	# print("Auth", mma.authenticate())

	# dcm = DFAGrabber('dcm/conf')

	# print( dcm.fill_url("/auth/dfareporting/v2.2/userprofiles/%s/accounts", dcm.profile_id))

	# print(mma.urls)
	tm = TubeMogulGrabber('tubemogul/conf')
	print("Auth", tm.authenticate())

	# parameters = {'filter':'agency_id=100480',
	# 	'dimensions':'campaign_name,tpas_placement_name,strategy_name',
	# 	'start_date':'2015-09-23',
	# 	'end_date':'2015-10-11',
	# 	'time_rollup':'by_day',
	# 	'metrics':'impressions,margin,adserving_cost,adverification_cost,privacy_compliance_cost,contextual_cost,dynamic_creative_cost,media_cost,optimization_fee,pmp_no_opto_fee,pmp_opto_fee,platform_access_fee,mm_data_cost,mm_total_fee,total_ad_cost,billed_spend,total_spend'}

	# parameters = {'filter':'agency_id=100480&advertiser_id=149154&campaign_id=217122',
	# 	'dimensions':'campaign_name,strategy_name,exchange_name',
	# 	'start_date':'2015-09-23',
	# 	'end_date':'2015-10-11',
	# 	'time_rollup':'by_day',
	# 	'metrics':'impressions,total_spend,billed_spend,post_click_conversions,post_view_conversions,total_conversions'}

	# mma.authenticate()

	# print(mma.urls['performance'])

	# ro = requests.Request( method='get', url=mma.urls['performance'], params=parameters)

	# ro = mma.authenticate_request(ro)

	# mma.session.stream=True

	# resp = mma.send(ro)

	# mma.download_to_tmp(resp, 'mm-perform-data')
	# print("Done")

	# from pprint import pprint as pp
	# pp(resp.text)

	# print("Auth:", mma.has_auth())

