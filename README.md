# Repo Info

- repo for exporter that exposes security information about installed packages and CVE relevant info


### Enviroment variables list 

```
LOGGING_LEVEL - supports debug, info, warn, error ENUMS for logging level(Note this cannot be configuared via YAML file)
CVE_API_TIMEOUT - sets timeout for request to 3rd party api 
CVE_API_REQUEST_INTERVAL - sets time interval between each request  to avoid getting rate limited
CVE_API_URL - sets 3rd party API url which will have and endpoint that will give us cve-number info
CVE_API_ENDPOINT - sets 3rd party endpoint on which request will be sent to get info
CRON_EXPRESSION - this will basically set how many times this program will check for security updates and give CVE-number for them
```

- if you don't like using Enviroment variables you can use YAML config, please check [this link](./config/config.test.yaml)
