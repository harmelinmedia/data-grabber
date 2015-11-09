#!/usr/local/bin/python3

# base imports
import os, sys, json, logging
from datetime import datetime, timedelta
from base64 import b64encode, b64decode

# third-party library imports
import requests
from bs4 import BeautifulSoup

# local imports
from .errors import *

#GLOBAL VARs
DEFAULT_GRABBER_DIR = "~/.datagrabber"

# Conf objects
class Conf(object):

	"""Conf objects make config file definitions available as class attributes like so:

	{
		"name":"some-name",
		"urls": {
			"url1":"http://some.url",
			"url2":"http://some_other.url"
		}
		...etc...
	}

	These can be accessed as attributes of the Conf class, for example:

		$ print(self.name)
		some-name

		$ print(self.urls.url1)
		http://some.url

	"""

	_required_keys = []
	_init_keyerror_string = "Keys Missing: [%s] Configuration file must contain valid JSON with the following key defined: [%s]"

	def __init__(self, data):
		self.check_requirements(data)

	def check_requirements(self, data):
		# ensures that all necessary keys are defined in config
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
		logging.debug('Checking for non-auth directories')

		for key, val in data.items():
			if key != "auth":
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
					raise ConfInitUrlParseErrorAliasNotFound("URL alias %s not found. Please check url configurations in `conf` file." % val_split[0] )
			if set(key_queue) == set(retry_queue):
				raise ConfInitUrlParseErrorSelfReferringAlias("URL alias %s not found. Please check url configurations in `conf` file. Look for self-referential loop in aliased URL definitions." % val_split[0] )
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

	def __init__(self, config_file):
		logging.debug('Initializing Grabber')
		self._parse_conf(config_file) # load conf file
		self.credentials_file = self.cpath("credentials")
		self.token_file = self.cpath("token")
		self.refresh_file = self.cpath("refresh")
		self.credentials = self.prep_credentials() # set credentials
		self.session_refresh() # create Grabber session

	### class methods
	def _parse_conf(self, path):
		try:
			with open(path, 'r') as conf:
				data = json.load(conf)
		except Exception:
			raise GrabberInitFileError("Bad config file could not be read or parsed. Check to ensure file exists and contains valid JSON.\nPath: %s" % path)

		# check conf file compliance
		missing_keys = []
		for key in self._required_keys:
			if key not in data:
				missing_keys.append(key)
		if len(missing_keys) > 0:
			raise GrabberInitKeyError( "Key Missing: %s Configuration file \"%s\" must contain valid JSON with the following keys defined: [%s]" % (', '.join(missing_keys), path, ', '.join(self._required_keys) ) )

		self.files = FileConf( data["files"] )
		self.urls = URLConf( data["urls"] )
		self.dict_to_attr(data)

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

	def prep_credentials(self):
		try:
			with open(self.credentials_file, 'r') as fp:
				return self.parse_credentials(fp)
		except FileNotFoundError:
			raise GrabberAuthMissingCredentialsFile("Credentials file was not found at %s." % self.credentials_file )
		except Exception as e:
			raise GrabberAuthBadCredentialsFile("Credentials file could not be parsed.: "+e)

	def send(self, ro, stream=True):
		"""Authenticates request using `authenticate_request` method defined in subclass before sending"""
		logging.info('Sending request')
		ro = self.authenticate_request(ro)
		return self.session.send(ro.prepare())

	def authenticate(self):
		logging.debug('Authenticating...')
		try:
			test = self.test_auth()
			if test == False:
				self.refresh_auth_data()
				test = self.test_auth()
			return test
		except requests.exceptions.ConnectionError:
			raise GrabberHTTPConnectionError("Connection could not be established. You may not be connected to the Internet.")

	def request(self, url, method="get", headers=None, params=None, data=None, stream=False, urlargs=()):
		"""Wrapper method to make an authenticated request in a single function call"""
		ro = requests.Request(method=method, url=self.fill_url(url, *urlargs), headers=headers, params=params, data=data)
		self.session.stream = stream
		return self.send(ro)

	def fill_url(self, url, *args):
		return url % args

	def test_auth(self, *urlargs, **requestargs):
		logging.debug('Testing authentication...',)
		ro = requests.Request(
					method = 'GET',
					url = self.fill_url( self.urls.test, *urlargs),
					**requestargs
					)
		resp = self.send(ro)
		if resp.status_code == requests.codes.ok:
			return True
		else:
			logging.debug(resp.text)
			return False

	def download_to_tmp(self, ro, fname, ext='.csv', chunk_size_mb=5):
		"""takes streaming request object and saves to temporary file, default chunk size is 5 Mb"""
		logging.info('Saving temp file')
		filepath = os.path.join( self.files.tmp, '_'.join([ 'tmp', self.name, fname, self.timestamp() ]) + ext )
		with open( filepath, 'wb' ) as fout:
			for chunk in ro.iter_content( chunk_size= chunk_size_mb * 2**20): #n mb per chunk
				if chunk:
					fout.write(chunk)
					fout.flush()
		return filepath

	def request_download(self, url, fname, ext=".csv", method="get", headers=None, params=None, data=None, stream=True, urlargs=()):
		"""Wrapper method to make a request a download data in the same function call"""
		ro = self.request(url=url, method=method, headers=headers, params=params, data=data, stream=stream, urlargs=urlargs )
		if ro.status_code == 200:
			return self.download_to_tmp(ro=ro, fname=fname, ext=ext)
		else:
			raise GrabberRequestDownloadResourceError("Request Download failed at %s with status code %s." % (ro.url, str(ro.status_code)))

	### subclass methods
	def save_auth_to_file(self, text):
		with open(self.token_file, 'w') as af:
			af.write(text)

	def load_auth_from_file(self):
		try:
			with open(self.token_file, 'r') as tk:
				return self.parse_auth_data(tk)
		except (FileNotFoundError, GrabberAuthBadAuthFile, json.decoder.JSONDecodeError, KeyError):
			self.refresh_auth_data()
			with open(self.token_file, 'r') as tk:
				return self.parse_auth_data(tk)

	def parse_credentials(self, fp):
		return json.load(fp)
	
	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		raise NotImplementedError

	def parse_auth_data(self, fp):
		"""Parses auth file, raises Exception if not successful"""
		raise NotImplementedError

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		raise NotImplementedError

class TubeMogulGrabber(Grabber):

	def __init__(self, config_file = os.path.join(DEFAULT_GRABBER_DIR,"apis","tubemogul","conf")):
		super().__init__(config_file)

	def parse_credentials(self, fp):
		return json.load(fp)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = {"Authorization": "Bearer " + token}
		return ro

	def parse_auth_data(self, fp):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		auth = json.load(fp)
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

		response = self.session.post( self.urls.auth, headers=header, data=params)

		if response.status_code == requests.codes.ok:
			response_data = json.loads(response.text)
			response_data['expires_at'] = (datetime.utcnow() + timedelta(seconds=int(response_data['expires_in']))).strftime("%Y%m%d%H%M%S")
			self.save_auth_to_file(json.dumps(response_data))
		else:
			raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


class MediaMathGrabber(Grabber):

	def __init__(self, config_file = os.path.join(DEFAULT_GRABBER_DIR,"apis","mediamath","conf")):
		super().__init__(config_file)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		auth = self.load_auth_from_file()
		ro.cookies = auth
		return ro

	def parse_auth_data(self, fp):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		cookie = BeautifulSoup(fp.read(), "html.parser")
		if datetime.strptime(cookie.result.session['expires'], "%Y-%m-%dT%H:%M:%S") - datetime.utcnow() > timedelta(hours=1):
			return {'adama_session': cookie.result.session['sessionid']}
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

	def test_auth(self, *urlargs ):
		return super().test_auth(self.profile_id, *urlargs)

	def parse_credentials(self, fp):
		return json.load(fp)['installed']

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = {"Authorization": "Bearer " + token}
		return ro

	def parse_auth_data(self, fp):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		auth = json.load(fp)
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
				self.save_auth_to_file(json.dumps(response_data))
			else:
				raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')

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
				self.save_auth_to_file(json.dumps(response_data))
				with open(self.refresh_file, 'w') as out:
					json.dump(response_data, out)
			else:
				raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


class DCMGrabber(GoogleGrabber):
	scope = ['https://www.googleapis.com/auth/dfareporting']
	def __init__(self, config_file = os.path.join(DEFAULT_GRABBER_DIR,"apis","dcm","conf")):
		super().__init__(config_file)


class GoogleAnalyticsGrabber(GoogleGrabber):
	scope = ['https://www.googleapis.com/auth/analytics.readonly']
	def __init__(self, config_file = os.path.join(DEFAULT_GRABBER_DIR,"apis","googleanalytics","conf")):
		super().__init__(config_file)


class PointrollGrabber(Grabber):

	def __init__(self, config_file = os.path.join(DEFAULT_GRABBER_DIR,"apis","pointroll","conf")):
		super().__init__(config_file)

	def default_headers(self, **kwargs):
		headers = {
			'Content-Type':'application/json; charset=utf-8',
			'Accept':'application/json; charset=utf-8',
			"Scope_AgencyID" : str(self.agency_id),
			"Scope_AdvertiserID" : "",
			"Scope_CampaignID" : "",
			"Scope_PublisherID" : "",
			"Scope_SubPublisherID" : ""
		}
		for arg, val in kwargs.items():
			headers[arg] = val
		return headers

	def test_auth(self, *urlargs ):
		return super().test_auth(headers=self.default_headers(), *urlargs)

	def authenticate_request(self, ro):
		"""takes Request() object as argument, applies authorization method, returns modified Request() object"""
		token = self.load_auth_from_file()
		ro.headers = self.default_headers()
		ro.headers["token"] = token
		return ro

	def parse_auth_data(self, fp):
		"""Parses auth file, returns data, raises exception if unsuccessful"""
		auth = json.load(fp)
		if datetime.strptime(auth['expires_at'], "%Y%m%d%H%M%S") - datetime.utcnow() > timedelta(minutes=30):
			return auth['token']
		raise GrabberAuthBadAuthFile("Authentication data could not be loaded. File was broken, expired, or did not exist.")

	def refresh_auth_data(self):
		"""Gets new authorization data from API, saves to file"""
		logging.debug("Renewing authorization")
		response = self.session.post( self.urls.auth, params=self.credentials, headers=self.default_headers())
		if response.status_code == requests.codes.ok:
			response_data = dict(response.headers)
			response_data['expires_at'] = (datetime.utcnow() + timedelta(hours=12)).strftime("%Y%m%d%H%M%S")
			self.save_auth_to_file(json.dumps(response_data))
		else:
			raise GrabberAuthInvalidCredentials('Credentials invalid. Authorization not granted.')


if __name__=="__main__":

	logging.basicConfig(stream=sys.stdout, filename="dev-debug.log", level=logging.DEBUG) ## for local debugging
