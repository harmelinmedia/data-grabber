#Data Grabber

A framework for reliable ETL from REST API data sources.

Example Configuration File
```
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
```

# TO DO
* Set up package to use ~/.datagrabber as default config dir
* set up package to be imported as system package
* write "install" script to put on correct system path
* develop scheduler

# MAYBES
* add auth credentials to conf file?


