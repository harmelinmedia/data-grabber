class ConfError(Exception):
	pass

class ConfInitError(ConfError):
	pass

class ConfInitKeyError(ConfInitError, KeyError):
	pass

class ConfInitUrlParseError(ConfInitError):
	pass

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

class GrabberInitKeyError(GrabberError, KeyError):
	pass

class GrabberInitFileError(GrabberError, OSError):
	pass
	
