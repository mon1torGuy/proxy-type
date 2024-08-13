export interface KeyDetails {
	rl: {
		limit: number;
		timeWindow: number;
	};
}
export interface KeyDetailsRemaining {
	remaining: number;
}
export interface KeyUsageEvent {
	accID: string;
	appID: string;
	keyID: string;
	success: number;
	appName: string;
	ipAddress: number;
	userAgent: string;
	metadata?: Record<string, unknown>;
}

export interface KVMetadata {
	act: boolean;
	exp: number;
	rl: { limit: number; timeWindow: number } | null;
	rf: { amount: number; interval: number } | null;
	re: number | null;
	name: string;
}

export interface appTypeKVObject {
	appID: string;
	headerName: string;
	authType: string;
	hostname: string;
	emailDisp: string;
	LLMcache: string;
}
