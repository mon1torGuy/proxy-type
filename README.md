

# File structure

## All the proxy rely in a KV file that containes a JSON format for the whole configuration.

### below are the TS type
``` ts
export interface LLMCacheType {
	enabled: boolean;
	path: string[];
	provider: string;
	model: string;
	apikey: string;
	verbosity: number;
	similarity: number;
}

export interface EmailDispType {
	enabled: boolean;
	path: string[];
	exceptions: string[];
	blocklist: string[];
	checkLocations: "body" | "header" | "query";
	checkPropertyName: string;
}

export interface apiCacheType {
	enabled: boolean;
	cacheKey: string;
	path: string[];
}

export interface JWTType {
	enabled: boolean;
	path: string[];
	JWKS: string;
}
export interface appTypeKVObject {
	appID: string;
	headerName: string;
	authType: string;
	JWT: JWTType | null;
	hostname: string;
	LLMCache: LLMCacheType | null;
	emailDisp: EmailDispType | null;
	apiCache: apiCacheType | null;
}
```

### The object is fetch from the kv using  the application domain as key and the JSON object  is like this:

```json
{
    "appID": "123456789",
    "headerName": "Authorization",
    "authType": "token",
    "hostname": "jfkdls.12345789.typeauth.com",
    "LLMCache": {
        "enabled": true,
        "path": ["/queryai", "query"],
        "provider": "openai",
        "model": "gpt4o",
        "apikey": "123456789",
        "verbosity": 1,
        "similarity": 95
    },
    "emailDisp": {
        "enabled": true,
        "path": ["/login", "/auth"],
        "exceptions": [],
        "blocklist": [],
        "checkLocations": "header",
        "checkPropertyName": "Authorization"
    },
    "apiCache": {
        "enabled": true,
        "path": ["*"],
        "cacheKey": "thisis:the:cachekey"
    },
    "JWT" : {
        "enabled": true,
        "path": ["*"],
        "JWKS": "ijfdnvfjidnjvkdjfieonjskdijefonjkvdewd"
    }
}
```

### Also there are other KV needed like: 

- *typeauth_keys*: Which contain the opaque tokens issued by Typeauth
- *refill_timestamp*: contain the UNIX timestamp when a key was refilled last time
- *proxy_conf*: Contains all the application and services information
