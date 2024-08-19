import type { WorkerEntrypoint } from "cloudflare:workers";

export interface KeyDetails {
	rl: {
		limit: number;
		timeWindow: number;
	};
}

export interface Ratelimit {
	limit: number;
	timeWindow: number;
}

export interface RefillType {
	timestamp: number;
	amount: number;
}

export interface KeyDetailsRemaining {
	remaining: number;
}
export interface Refill {
	amount: number;
	interval: number;
}
export interface KeyUsageEvent {
	accID: string;
	appID: string;
	keyID: string;
	success: number;
	appName: string;
	ipAddress: number;
	userAgent: string;
	eventType: string;
}

export interface KVMetadata {
	act: boolean;
	exp: number;
	rl: { limit: number; timeWindow: number } | null;
	rf: { amount: number; interval: number } | null;
	re: number | null;
	name: string;
}

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
	checkLocations: string;
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

export interface KeyKVValue {
	appID: string;
	id: string;
	accId: string;
	rateLimit: Ratelimit;
	remain: number;
	enabled: boolean;
	refill: Refill;
	expiration: number;
}
type RateLimitResponse = {
	success: boolean;
	message: string;
	data: number;
};

type RemainResponse = {
	success: boolean;
	message: string;
	data: number;
};

type LLMCacheResponse = {
	success: boolean;
	message: string;
	data: string;
};

type AbuseCheckResponse = {
	success: boolean;
	message: string;
	data: number;
};
export interface RateType extends WorkerEntrypoint {
	ratelimitGet: (key: string) => Promise<RateLimitResponse>;
	ratelimit: (key: string) => Promise<RateLimitResponse>;
	ratelimitSet: (
		key: string,
		ratelimit: { limit: number; timeWindow: number },
	) => Promise<RateLimitResponse>;
}

export interface RemainType extends WorkerEntrypoint {
	remainGet: (key: string) => Promise<RemainResponse>;
	remain: (key: string) => Promise<RemainResponse>;
	remainSet: (key: string, remain: number) => Promise<RemainResponse>;
}

export interface AbuseServiceType extends WorkerEntrypoint {
	checkDisposable: (email: string) => Promise<AbuseCheckResponse>;
}

export interface LLMCacheServiceType extends WorkerEntrypoint {
	cache: (
		query: string,
		model: string,
		provider: string,
		verbosity: number,
		apikey: string,
		similarity: number,
	) => Promise<LLMCacheResponse>;
}

export interface PerformanceMetrics {
	total: number;
	configurationRetrieval: number;
	tokenExtraction: number;
	authentication: number;
	rateLimit: number;
	remain: number;
	refill: number;
	abuseCheck: number;
	llmCache: number;
	apiCache: number;
}
