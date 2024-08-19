export const test = {
	appID: "123456789",
	headerName: "Authorization",
	authType: "token",
	hostname: "jfkdls.12345789.typeauth.com",
	LLMCache: {
		enabled: true,
		path: ["/queryai", "query"],
		provider: "openai",
		model: "gpt4o",
		apikey: "123456789",
		verbosity: 1,
		similarity: 95,
	},
	emailDisp: {
		enabled: true,
		path: ["/login", "/auth"],
		exceptions: [],
		blocklist: [],
		checkLocations: "header",
		checkPropertyName: "Authorization",
	},
	apiCache: {
		enabled: true,
		path: ["*"],
		cacheKey: "thisis:the:cachekey",
	},
	JWT: {
		enabled: true,
		path: ["*"],
		JWKS: "ijfdnvfjidnjvkdjfieonjskdijefonjkvdewd",
	},
};
