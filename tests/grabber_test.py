#library imports
import copy, os
from pprint import pprint as pp
from io import StringIO as stio

# modules to test
from ..grabber.grabber import *
from ..grabber.errors import *

# for testing config files and init procedures
api_path = "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/apis/"
for api in ["dcm","mediamath","tubemogul"]:
	exec( "%s_path = os.path.join(api_path, \"%s\", \"conf\")" % (api,api) )

class TestGrabber:

	# def test_config_file_open(self, tmpdir):
	# 	p = tmpdir.mkdir("doop").join("conf")
	# 	p.write(json.dumps(gconf))
	# 	grab = MediaMathGrabber(p.strpath)
	# 	# assert 0

	def test_mediamath_config(self, tmpdir):
		g = MediaMathGrabber(mediamath_path)
		assert g.name == 'mediamath'
		assert g.files.auth == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/apis/mediamath"
		assert g.files.tmp == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/data"
		assert g.urls.base == "https://api.mediamath.com/reporting/v1/std"
		assert g.urls.test == "https://api.mediamath.com/reporting/v1/std/meta"
		assert g.urls.auth == "https://api.mediamath.com/api/v2.0/login"

	def test_dcm_config(self, tmpdir):
		g = DCMGrabber(dcm_path)
		assert g.name == 'dcm'
		assert g.files.auth == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/apis/dcm"
		assert g.files.tmp == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/data"
		assert g.urls.base == "https://www.googleapis.com/dfareporting/v2.2"
		assert g.urls.test == "https://www.googleapis.com/dfareporting/v2.2/userprofiles/%s"
		assert g.urls.auth == "https://accounts.google.com/o/oauth2"

	def test_tubemogul_config(self, tmpdir):
		g = TubeMogulGrabber(tubemogul_path)
		assert g.name == 'tubemogul'
		assert g.files.auth == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/apis/tubemogul"
		assert g.files.tmp == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/data"
		assert g.urls.base == "https://api.tubemogul.com"
		assert g.urls.auth == "http://api.tubemogul.com/oauth/token"
		assert g.urls.test == "https://api.tubemogul.com/v1/trafficking/campaigns?limit=1&offset=0"

	def test_mediamath_auth(self):
		g = MediaMathGrabber(mediamath_path)
		try:
			assert g.authenticate()
		except GrabberHTTPConnectionError:
			assert 1

	def test_tubemogul_auth(self):
		g = TubeMogulGrabber(tubemogul_path)
		try:
			assert g.authenticate()
		except GrabberHTTPConnectionError:
			assert 1

	def test_dcm_auth(self):
		g = DCMGrabber(dcm_path)
		try:
			assert g.authenticate()
		except GrabberHTTPConnectionError:
			assert 1

