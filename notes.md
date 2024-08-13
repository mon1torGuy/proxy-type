


# Keys 

Should contain the following information will be stored in this KV: 'api-typeauth-keys'

- appID: The ID of the application
- accId: The ID of the account
- RateLimit: Inherit from the Application
- Remain: Inherit from the Application
- enabled: Boolean
- Refill: Inherit from the application
- Expiration: Timestamp when key is disables

# Application

Should contain the following information will be stored in this KV: 'proxy-proxy_conf'

- appID: The ID of the application
- accId: The ID of the account
- headerName: Name of the header where the token will be present
- AuthType: Using TypeAuth tokens or JWT
- hostname: string;
- EmailDisp: Is Email Disposable enabled for this path
- LLMcache: Is LLM cachong enable for this path

