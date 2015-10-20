#library imports
import copy
from pprint import pprint as pp

# modules to test
from ..grabber.grabber import *
from ..grabber.errors import *


gconf = {
			"name": "tubemogul",
			"files": {
				"tmp": "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/data",
				"auth": "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/tubemogul"
				},
			"urls": {
				"base": "https://api.tubemogul.com",
				"auth": "$BASE/oauth/token",
				"reports": "$BASE/v1",
				"trafficking": "$REPORTS/trafficking",
				"test": "$TRAFFICKING/campaigns?limit=1&offset=0"
				}
		}


class TestConfs:

	def test_base(self):
		assert 1

	def test_FileConf_init_success(self):
		conf = copy.deepcopy(gconf)["files"]
		try:
			fc = FileConf(conf)
			assert 1
		except Exception:
			assert 0

	def test_FileConf_init_missingkeys_tmp(self):
		conf = copy.deepcopy(gconf)["files"]
		del conf["tmp"]
		try:
			fc = FileConf(conf)
			assert 0
		except ConfInitKeyError:
			assert 1

	def test_FileConf_init_missingkeys_auth(self):
		conf = copy.deepcopy(gconf)["files"]
		del conf["auth"]
		try:
			fc = FileConf(conf)
			assert 0
		except ConfInitKeyError:
			assert 1

	def test_URLConf_init_success(self):
		conf = copy.deepcopy(gconf)["urls"]
		try:
			fc = URLConf(conf)
			assert 1
		except ConfInitKeyError:
			assert 0

	def test_URLConf_init_missingkeys_auth(self):
		conf = copy.deepcopy(gconf)["urls"]
		del conf["auth"]
		try:
			fc = URLConf(conf)
			assert 0
		except ConfInitKeyError:
			assert 1

	def test_URLConf_init_urlparse_AliasNotFound(self):
		conf = copy.deepcopy(gconf)["urls"]
		del conf["reports"]
		try:
			fc = URLConf(conf)
			assert 0
		except ConfInitUrlParseErrorAliasNotFound:
			assert 1

	def test_URLConf_init_urlparse_SelfReferringAlias(self):
		conf = copy.deepcopy(gconf)["urls"]
		conf["base"] = "$AUTH/thing"
		try:
			fc = URLConf(conf)
			assert 0
		except ConfInitUrlParseErrorSelfReferringAlias:
			assert 1

	def test_FileConf_dicttoattr(self):
		fc = FileConf(gconf["files"])
		assert fc.tmp == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/data"
		assert fc.auth == "/Users/hank/Documents/Harmelin/Projects_Harmelin/datagrabber/tubemogul"

	def test_URLConf_dicttoattr(self):
		fc = URLConf(gconf["urls"])
		assert fc.base == "https://api.tubemogul.com"
		assert fc.auth == "https://api.tubemogul.com/oauth/token"
		assert fc.test == "https://api.tubemogul.com/v1/trafficking/campaigns?limit=1&offset=0"
