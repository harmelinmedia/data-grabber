import requests

class ConfError(Exception):
	pass


class ConfInitError(ConfError):
	pass

class ConfInitKeyError(ConfInitError, KeyError):
	pass

class ConfInitUrlParseErrorAliasNotFound(ConfInitError):
	pass

class ConfInitUrlParseErrorSelfReferringAlias(ConfInitError):
	pass



class GrabberError(Exception):
	pass


class GrabberAuthError(GrabberError):
	pass

class GrabberAuthBadAuthFile(GrabberAuthError):
	pass

class GrabberAuthFileNotFound(GrabberAuthError):
	pass

class GrabberAuthInvalidCredentials(GrabberAuthError):
	pass

class GrabberAuthMissingCredentialsFile(GrabberAuthError):
	pass

class GrabberAuthExpiredCredentials(GrabberAuthError):
	pass

class GrabberAuthBadCredentialsFile(GrabberAuthError):
	pass



class GrabberInitError(GrabberError):
	pass

class GrabberInitKeyError(GrabberError, KeyError):
	pass

class GrabberInitFileError(GrabberError, OSError):
	pass
	
class GrabberHTTPError(GrabberError, requests.exceptions.ConnectionError):
	pass

class GrabberHTTPConnectionError(GrabberHTTPError):
	pass

class GrabberRequestDownloadResourceError(GrabberError):
	pass
