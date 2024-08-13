import { importJWK, jwtVerify } from 'jose';

interface Env {
	typeauth_keys: KVNamespace;
	proxy_conf: KVNamespace;
	app_jwt_keys: KVNamespace;
	MASTER_API_TOKEN: string;
	R2RAW: R2Bucket;
	ANALYTICS: AnalyticsEngineDataset;
	RATE_LIMITER: DurableObjectNamespace;
	REMAINING: DurableObjectNamespace;
	DB: D1Database;
}

interface KeyDetails {
	rl: {
		limit: number;
		timeWindow: number;
	};
}
interface KeyDetailsRemaining {
	remaining: number;
}
interface KeyUsageEvent {
	accID: string;
	appID: string;
	keyID: string;
	appName: string;
	success: number;
	ipAddress: number;
	userAgent: string;
	metadata?: Record<string, unknown>;
}

interface KVMetadata {
	act: boolean;
	exp: number;
	rl: { limit: number; timeWindow: number } | null;
	rf: { amount: number; interval: number } | null;
	re: number | null;
	name: string;
}

interface appTypeKVObject {
	appID: string;
	headerName: string;
	authType: string;
	hostname: string;
}
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const host = request.headers.get('host');
		if (!host) {
			return unacceptable();
		}
		const app_configuration = await env.proxy_conf.get(host, { type: 'json' });
		if (!app_configuration) {
			return badRequest();
		}
		const { appID, headerName, authType, hostname } = app_configuration as appTypeKVObject;
		const token = await getAuthHeader(headerName, request, authType);

		if (token instanceof Response) {
			return token;
		}

		if (authType === 'jwt') {
			const keys = await env.app_jwt_keys.get(appID, { type: 'json' });
			if (!keys) {
				return forbidden();
			}

			let verified = false;
			let jwtError = false;
			for (let key of keys) {
				const jwtKey = await importJWK(key);
				try {
					await jwtVerify(token.value, jwtKey);
					verified = true;
					break;
				} catch (error) {
					jwtError = true;
				}
			}
			if (jwtError) {
				return internalServerError();
			}
			if (!verified) {
				return forbidden();
			}
			return await forwardRequest(hostname, request);  // Fixed this line
		}

		if (authType === 'type') {
			let verificationSuccess = false;
			let applicationID: string = '';
			let keyId: string = '';
			let accID: string = '';
			let jsonValue;
			let IPAdd = 0;
			if (request.headers.get('cf-connecting-ip') != null) {
				let ip = request.headers.get('cf-connecting-ip') || '';
				IPAdd = ipToDecimal(ip);
			}

			if (token.value) {
				jsonValue = JSON.parse(token.value);
				applicationID = jsonValue.appId;
				keyId = jsonValue.id;
				accID = jsonValue.accId;
			}
			if (applicationID != appID) {
				return unauthorized();
			}
			if (token.metadata) {
				if (!token.metadata.act) {
					return forbidden();
				}
				if (token.metadata.exp && token.metadata.exp < Date.now()) {
					return forbidden();
				}

				let rlObject = { limit: token.metadata.rl?.limit, timeWindow: token.metadata.rl?.timeWindow, remaining: 0 };
				if (token.metadata.rl != null) {
					const id = env.RATE_LIMITER.idFromName(token.value);
					const rateLimiter = env.RATE_LIMITER.get(id);
					const response = await rateLimiter.fetch(new Request(`https://ratelimiter?key=${token}`));
					const jsonResponse: { remaining: number } = await response.json();
					rlObject.remaining = jsonResponse.remaining;
					if (response.status === 429) {
						await logKeyUsageEvent(
							{
								accID: accID,
								appID: applicationID,
								keyID: keyId,
								appName: token.metadata.name,
								userAgent: request.headers.get('user-agent') || '',
								ipAddress: IPAdd,
								success: verificationSuccess ? 1 : 0,
								metadata: {
									userAgent: request.headers.get('user-agent') || '',
									ipAddress: IPAdd,
								},
							},
							env
						);
						return tooManyRequests();
					} else if (response.status === 401) {
						return forbidden();
					}
				}
				let remaObject = { remaining: 0 };
				if (token.metadata.re != null) {
					const id = env.REMAINING.idFromName(token.value);
					const bucket = env.REMAINING.get(id);
					const response = await bucket.fetch(new Request(`https://remainer?key=${token}`));
					const jsonResponse: { remaining: number } = await response.json();
					remaObject.remaining = jsonResponse.remaining;
					if (response.status === 200) {
						if (jsonResponse.remaining === 0) {
							token.metadata.act = false;
							jsonValue.enabled = false;
							await env.typeauth_keys.put(token.value, JSON.stringify(jsonValue), { metadata: token.metadata });
							const { success } = await env.DB.prepare('UPDATE keys SET enabled = false WHERE id = ?1').bind({ keyId }).run();
							if (!success) {
								return internalServerError();
							}
						}
					} else if (response.status === 429) {
						await logKeyUsageEvent(
							{
								accID: accID,
								appID: appID,
								keyID: keyId,
								appName: token.metadata.name,
								ipAddress: IPAdd,
								userAgent: request.headers.get('user-agent') || '',
								success: verificationSuccess ? 1 : 0,
								metadata: {
									userAgent: request.headers.get('user-agent') || '',
									ipAddress: IPAdd,
								},
							},
							env
						);
						return tooManyRequests();
					} else if (response.status === 401) {
						return forbidden();
					}
				}

				verificationSuccess = true; // Replace with your actual verification result

				await logKeyUsageEvent(
					{
						accID: accID,
						appID: appID,
						keyID: keyId,
						appName: token.metadata.name,
						ipAddress: IPAdd,
						userAgent: request.headers.get('user-agent') || '',
						success: verificationSuccess ? 1 : 0,
						metadata: {},
					},
					env
				);

				await forwardRequest(hostname, request);
			}
		}
		console.log(token);

		return new Response('Hello World!');
		// Helper function to get the Authorization header
		async function getAuthHeader(
			headerName: string,
			request: Request,
			authType: string
		): Promise<{ value: string; metadata: KVMetadata | null } | Response> {
			const authHeader = request.headers.get(headerName);
			if (!authHeader || authHeader === undefined) {
				return new Response('Unauthorized', {
					status: 401,
				});
			}
			const [type, key] = authHeader.split(' ');

			if (type !== 'Bearer') {
				return new Response('Unauthorized', {
					status: 401,
				});
			}
			if (authType === 'jwt') {
				return { value: key, metadata: null };
			}
			const { value, metadata } = await env.typeauth_keys.getWithMetadata<KVMetadata>(key);
			if (!value) {
				return new Response('Forbidden', {
					status: 403,
				});
			}
			if (!metadata) {
				return new Response('Forbidden', {
					status: 403,
				});
			}
			return { value, metadata };
		}

		//create a helper function that take a hostname and a request and forward the request to the backend
		async function forwardRequest(hostname: string, request: Request): Promise<Response> {
			const response = await fetch(hostname + request.url, {
				method: request.method,
				headers: request.headers,
				body: request.body,
			});
			//the response should be not modified
			return new Response(JSON.stringify(response), {
				status: response.status,
				statusText: response.statusText,
				headers: response.headers,
			});
		}

		//create a helper function to response when the request is not authorized
		function unauthorized(): Response {
			return new Response('Unauthorized', {
				status: 401,
			});
		}
		// create a helper function to response when the request is not found
		function notFound(): Response {
			return new Response('Not Found', {
				status: 404,
			});
		}

		// create a helper function to response when the request is forbidden
		function forbidden(): Response {
			return new Response('Forbidden', {
				status: 403,
			});
		}
		// create a helper function to response when the request is bad request
		function badRequest(): Response {
			return new Response('Bad Request', {
				status: 400,
			});
		}

		// create a helper function to response when the request is unacceptable
		function unacceptable(): Response {
			return new Response('Unacceptable', {
				status: 406,
			});
		}

		// create a helper function to response when the request is too long
		function tooLong(): Response {
			return new Response('Too Long', {
				status: 413,
			});
		}

		// create a helper function to response when the request is too many requests
		function tooManyRequests(): Response {
			return new Response('Too Many Requests', {
				status: 429,
			});
		}

		// create a helper function to response when the request is internal server error
		function internalServerError(): Response {
			return new Response('Internal Server Error', {
				status: 500,
			});
		}

		// create a helper function to response when the request is service unavailable
		function serviceUnavailable(): Response {
			return new Response('Service Unavailable', {
				status: 503,
			});
		}
		async function logKeyUsageEvent(event: KeyUsageEvent, env: Env): Promise<void> {
			const { accID, appID, appName, keyID, success, metadata, ipAddress, userAgent } = event;
			env.ANALYTICS.writeDataPoint({
				blobs: [accID, appID, keyID, userAgent, appName],
				doubles: [success, ipAddress],
				indexes: [keyID],
			});
		}

		// Helper function to gather headers and send to R2 bucket
	},
};

export class RateLimiter {
	private state: DurableObjectState;
	private env: Env;

	constructor(state: DurableObjectState, env: Env) {
		this.state = state;
		this.env = env;
	}

	async fetch(request: Request): Promise<Response> {
		const { searchParams } = new URL(request.url);
		const key = searchParams.get('key');
		const init = searchParams.get('init');
		const set = searchParams.get('set');

		if (!key) {
			return new Response(JSON.stringify({ error: 'Key is required' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (init) {
			await this.state.storage.put(key, set);
			return new Response(JSON.stringify(set), {
				status: 201,
				headers: { 'Content-Type': 'application/json' },
			});
		}
		// Retrieve the key details from storage or database
		const keyDetails = await this.getKeyDetails(key);

		if (!keyDetails) {
			return new Response(JSON.stringify({ error: 'Invalid key' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		const { limit, timeWindow } = keyDetails.rl;

		const now = Date.now() / 1000; // Current timestamp in seconds

		const storageValue = await this.state.storage.get<{ value: number; expiration: number }>(key);
		let value = storageValue?.value || 0;
		let expiration = storageValue?.expiration || now + timeWindow;

		if (now < expiration) {
			if (value >= limit) {
				return new Response(JSON.stringify({ error: 'Rate limit exceeded', remaining: 0 }), {
					status: 429,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			value++;
		} else {
			value = 1;
			expiration = now + timeWindow;
		}

		await this.state.storage.put(key, { value, expiration });

		const remaining = limit - value;

		return new Response(JSON.stringify({ remaining }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	async getKeyDetails(key: string): Promise<KeyDetails | null> {
		const keyDetailsJson = await this.env.typeauth_keys.getWithMetadata(key);
		if (keyDetailsJson.metadata) {
			return keyDetailsJson.metadata as KeyDetails;
		}
		return null;
	}
}

export class Remaining {
	private state: DurableObjectState;
	private env: Env;

	constructor(state: DurableObjectState, env: Env) {
		this.state = state;
		this.env = env;
	}

	async fetch(request: Request): Promise<Response> {
		const { searchParams } = new URL(request.url);
		const key = searchParams.get('key');
		const set = searchParams.get('set');
		const init = searchParams.get('init');
		const get = searchParams.get('get');
		if (!key) {
			return new Response(JSON.stringify({ error: 'Key is required' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (get) {
			let remaining = await this.state.storage.get(key);
			return new Response(JSON.stringify({ remaining: remaining }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (init) {
			if (!set) {
				return new Response(JSON.stringify({ error: 'set is missing' }), {
					status: 401,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			await this.state.storage.put(key, parseInt(set));
			return new Response(JSON.stringify({ remaining: set }), {
				status: 201,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Retrieve the key details from storage or database
		const keyDetails = await this.getKeyDetails(key);

		if (!keyDetails) {
			return new Response(JSON.stringify({ error: 'Invalid key' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		let remaining = await this.state.storage.get<number>(key);

		if (remaining === undefined) {
			return new Response(JSON.stringify({ error: 'Invalid key' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (remaining <= 0) {
			return new Response(JSON.stringify({ error: 'Usage limit exceeded', remaining: 0 }), {
				status: 429,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		await this.state.storage.put(key, remaining - 1);

		return new Response(JSON.stringify({ remaining: remaining - 1 }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	async getKeyDetails(key: string): Promise<KeyDetailsRemaining | null> {
		const keyDetailsJson = await this.env.typeauth_keys.get(key);
		if (keyDetailsJson) {
			return JSON.parse(keyDetailsJson) as KeyDetailsRemaining;
		}
		return null;
	}
}

function ipToDecimal(ipAddress: string): number {
	// Split the IP address into octets (sections)
	const octets = ipAddress.split('.');

	// Validate the format (4 octets, each between 0 and 255)
	if (octets.length !== 4 || !octets.every((octet) => isValidOctet(octet))) {
		return 0;
	}

	// Convert each octet to a number and shift/add for final decimal value
	return octets.reduce((decimal, octet, index) => {
		const octetValue = parseInt(octet, 10);
		return decimal + octetValue * Math.pow(256, 3 - index);
	}, 0);
}

function isValidOctet(octet: string): boolean {
	const octetValue = parseInt(octet, 10);
	return !isNaN(octetValue) && octetValue >= 0 && octetValue <= 255;
}
