import { test } from "../example";
import {
	badRequest,
	forbidden,
	forwardRequest,
	getAuthHeader,
	ipToDecimal,
	logKeyUsageEvent,
	tooManyRequests,
	unacceptable,
	unauthorized,
	handleAPICache,
} from "./helpers";
import type {
	AbuseServiceType,
	appTypeKVObject,
	KeyKVValue,
	LLMCacheServiceType,
	PerformanceMetrics,
	RateType,
	RefillType,
	RemainType,
} from "./types";

interface Env {
	typeauth_keys: KVNamespace;
	refill_timestamp: KVNamespace;
	proxy_conf: KVNamespace;
	RATELIMIT: Service<RateType>;
	REMAIN: Service<RemainType>;
	LLMCACHE: Service<LLMCacheServiceType>;
	ABUSE: Service<AbuseServiceType>;
	ANALYTICS: AnalyticsEngineDataset;
}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const startTime = performance.now();
		const metrics: PerformanceMetrics = {
			total: 0,
			configurationRetrieval: 0,
			tokenExtraction: 0,
			authentication: 0,
			rateLimit: 0,
			remain: 0,
			refill: 0,
			abuseCheck: 0,
			llmCache: 0,
			apiCache: 0,
		};
		//Check if host is present in the request
		const host = request.headers.get("host");
		const url = new URL(request.url);
		const path = url.pathname;
		const isMetric = url.searchParams.get("metrics");

		if (!host) {
			return unacceptable();
		}

		const metadata = request.cf;
		if (!metadata) {
			return badRequest();
		}
		const ip = request.headers.get("cf-connecting-ip");
		const userAgent = request.headers.get("user-agent");
		const metaPayload = { ...metadata, ip, host };

		const configStartTime = performance.now();
		const proxyConfiguration = (await env.proxy_conf.get(host, {
			type: "json",
		})) as unknown as appTypeKVObject;

		metrics.configurationRetrieval = performance.now() - configStartTime;
		if (!proxyConfiguration) {
			return badRequest();
		}
		console.log("proxyConfiguration", proxyConfiguration);

		//Check if all the proxyconfiguration properties are present and apply conditions
		if (
			!proxyConfiguration.appID ||
			!proxyConfiguration.headerName ||
			!proxyConfiguration.authType ||
			!proxyConfiguration.hostname
		) {
			return badRequest();
		}

		const appID = proxyConfiguration.appID;
		const headerName = proxyConfiguration.headerName;
		const authStartTime = performance.now();

		const tokenExtractTime = performance.now();
		const tokenExtract = await getAuthHeader(
			headerName,
			request,
			proxyConfiguration.authType,
			env,
		);
		console.log("tokenExtract", tokenExtract);
		const token = tokenExtract.success ? tokenExtract.data : null;

		if (!token) {
			return forbidden();
		}

		metrics.tokenExtraction = performance.now() - tokenExtractTime;
		//First we apply authentication
		// TODO: We need to implement JWT verification, create the table relation between the appID and the JWT and create the KV wich holds the JWKs
		// if (proxyConfiguration.authType === "jwt") {
		// 	const keys = await pri
		// 	if (!keys) {
		// 		return forbidden();
		// 	}

		// 	let verified = false;
		// 	let jwtError = false;
		// 	for (const key of keys) {
		// 		const jwtKey = await importJWK(key);
		// 		try {
		// 			await jwtVerify(token.value, jwtKey);
		// 			verified = true;
		// 			break;
		// 		} catch (error) {
		// 			jwtError = true;
		// 		}
		// 	}
		// 	console.log(verified);
		// 	if (jwtError) {
		// 		return internalServerError();
		// 	}
		// 	if (!verified) {
		// 		return forbidden();
		// 	}
		// }

		if (proxyConfiguration.authType === "type") {
			metrics.authentication = performance.now() - authStartTime;

			const KeyValue = token.value as unknown as KeyKVValue;

			// Check if the key is enabled
			if (!KeyValue.enabled) {
				await logKeyUsageEvent(
					{
						accID: KeyValue.accId,
						appID: KeyValue.appID,
						keyID: KeyValue.id,
						appName: proxyConfiguration.hostname,
						userAgent: userAgent || "",
						ipAddress: ipToDecimal(metaPayload.ip || "0.0.0.0"),
						eventType: "disabled",
						success: 1,
					},
					env,
				);
				return forbidden();
			}
			// Check if application ID matches
			if (KeyValue.appID !== proxyConfiguration.appID) {
				return unauthorized();
			}

			// Check if the key is expired
			if (KeyValue.expiration && KeyValue.expiration < Date.now()) {
				await logKeyUsageEvent(
					{
						accID: KeyValue.accId,
						appID: KeyValue.appID,
						keyID: KeyValue.id,
						appName: proxyConfiguration.hostname,
						userAgent: userAgent || "",
						ipAddress: ipToDecimal(metaPayload.ip || "0.0.0.0"),
						eventType: "expired",
						success: 1,
					},
					env,
				);
				return forbidden();
			}
			const rateLimitStartTime = performance.now();

			// Check  rate limit
			if (KeyValue.rateLimit && KeyValue.rateLimit !== null) {
				// reject if the rate limit is exceeded
				const rlResult = await env.RATELIMIT.ratelimit(token.value);
				if (rlResult.success) {
					if (rlResult.data === 0) {
						await logKeyUsageEvent(
							{
								accID: KeyValue.accId,
								appID: KeyValue.appID,
								keyID: KeyValue.id,
								appName: proxyConfiguration.hostname,
								userAgent: userAgent || "",
								ipAddress: ipToDecimal(metaPayload.ip || "0.0.0.0"),
								eventType: "ratelimit",
								success: 1,
							},
							env,
						);
						return tooManyRequests();
					}
				}
			}
			metrics.rateLimit = performance.now() - rateLimitStartTime;
			const remainStartTime = performance.now();

			//Check if the key is remained
			if (KeyValue.remain && KeyValue.remain !== null) {
				// reject if the remain is exceeded
				const remainResult = await env.REMAIN.remain(token.value);
				if (remainResult.success) {
					if (remainResult.data === 0) {
						await logKeyUsageEvent(
							{
								accID: KeyValue.accId,
								appID: KeyValue.appID,
								keyID: KeyValue.id,
								appName: proxyConfiguration.hostname,
								userAgent: userAgent || "",
								ipAddress: ipToDecimal(metaPayload.ip || "0.0.0.0"),
								eventType: "remain",
								success: 1,
							},
							env,
						);
						return tooManyRequests();
					}
				}
			}
			metrics.remain = performance.now() - remainStartTime;
			const refillStartTime = performance.now();

			// Check if the key is refilled
			if (KeyValue.refill && KeyValue.refill !== null) {
				// reject if the refill is exceeded
				const refillResult = (await env.refill_timestamp.get(token.value, {
					type: "json",
				})) as unknown as RefillType;
				if (refillResult.timestamp && refillResult.timestamp < Date.now()) {
					const updateRemain = await env.REMAIN.remainSet(
						token.value,
						refillResult.amount,
					);
					if (updateRemain.success) {
						await logKeyUsageEvent(
							{
								accID: KeyValue.accId,
								appID: KeyValue.appID,
								keyID: KeyValue.id,
								appName: proxyConfiguration.hostname,
								userAgent: userAgent || "",
								ipAddress: ipToDecimal(metaPayload.ip || "0.0.0.0"),
								eventType: "refilled",
								success: 1,
							},
							env,
						);
					}
				}
			}
			metrics.refill = performance.now() - refillStartTime;
		}

		//Check for Abuse and Security
		const abuseStartTime = performance.now();

		if (proxyConfiguration.emailDisp?.enabled) {
			//Check if path match proxyConfiguration.emailDisp.path
			if (proxyConfiguration.emailDisp.path.includes(path)) {
				let email = null;
				// Get the email from the body
				if (proxyConfiguration.emailDisp.checkLocations === "body") {
					const body = await request.clone().text();
					const bodyEmail = body.match(/<[^<>]+@[^<>]+>/g);
					if (bodyEmail) {
						email = bodyEmail[0].replace(/<|>/g, "");
					}
				}
				// Check if the email is in the header
				if (proxyConfiguration.emailDisp.checkLocations === "header") {
					const headerEmail = request.headers.get(
						proxyConfiguration.emailDisp.checkPropertyName,
					);
					if (headerEmail) {
						email = headerEmail;
					}
				}
				// Check if the email is in the query
				if (proxyConfiguration.emailDisp.checkLocations === "query") {
					const queryEmail = url.searchParams.get(
						proxyConfiguration.emailDisp.checkPropertyName,
					);
					if (queryEmail) {
						email = queryEmail;
					}
				}

				if (!email) {
					return forbidden();
				}

				const abuseCheclResult = await env.ABUSE.checkDisposable(email);
				if (abuseCheclResult.success) {
					if (abuseCheclResult.data === 1) {
						return forbidden();
					}
				}
			}
		}
		metrics.abuseCheck = performance.now() - abuseStartTime;
		const llmCacheStartTime = performance.now();

		if (proxyConfiguration.LLMCache?.enabled) {
			// Check if path match proxyConfiguration.LLMCache.path
			if (proxyConfiguration.LLMCache.path.includes(path)) {
				// Take the query from the JSON body
				const { query } = (await request.json()) as unknown as {
					query: string;
				};

				const LLMCache = await env.LLMCACHE.cache(
					query,
					proxyConfiguration.LLMCache.model,
					proxyConfiguration.LLMCache.provider,
					proxyConfiguration.LLMCache.verbosity,
					proxyConfiguration.LLMCache.apikey,
					proxyConfiguration.LLMCache.similarity,
				);

				if (LLMCache.success) {
					if (LLMCache.data) {
						return new Response(LLMCache.data, {
							status: 200,
							headers: { "Content-Type": "application/json" },
						});
					}
				}
			}
		}
		metrics.llmCache = performance.now() - llmCacheStartTime;
		const apiCacheStartTime = performance.now();

		if (proxyConfiguration.apiCache?.enabled) {
			// Check if path match proxyConfiguration.apiCache.path
			if (proxyConfiguration.apiCache.path.includes(path)) {
				// Take the query from the JSON body

				return await handleAPICache(request, ctx);
			}
		}
		metrics.apiCache = performance.now() - apiCacheStartTime;
		///forwardRequest(proxyConfiguration.hostname, request);
		metrics.total = performance.now() - startTime;

		if (isMetric) {
			return new Response(JSON.stringify(metrics), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		return new Response("Hello World!");
	},
};
