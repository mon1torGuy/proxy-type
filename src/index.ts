import { importJWK, jwtVerify } from "jose";
import {
	badRequest,
	forbidden,
	getAuthHeader,
	internalServerError,
	unacceptable,
} from "./helpers";
import type { appTypeKVObject, KeyDetails, KeyDetailsRemaining } from "./types";

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

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		//Check if host is present in the request
		const host = request.headers.get("host");
		if (!host) {
			return unacceptable();
		}
		const metadata = request.cf;
		if (!metadata) {
			return badRequest();
		}
		const ip = request.headers.get("cf-connecting-ip");

		const metaPayload = { ...metadata, ip, host };
		//Get the app configuration from the proxy_conf KV
		const app_configuration = await env.proxy_conf.get(host, { type: "json" });
		if (!app_configuration) {
			return badRequest();
		}
		//Get the appID, headerName, authType, hostname, emailDisp, LLMcache from the app configuration
		const { appID, headerName, authType, hostname, emailDisp, LLMcache } =
			app_configuration as appTypeKVObject;
		//Get the token from the request
		const token = await getAuthHeader(headerName, request, authType, env);

		//Check if the token is a response
		if (!token.success) {
			return forbidden();
		}
		//Check if the authType is jwt
		// if (authType === "jwt") {
		// 	const keys = await env.app_jwt_keys.get(appID, { type: "json" });
		// 	if (!keys) {
		// 		return forbidden();
		// 	}

		// 	let verified = false;
		// 	let jwtError = false;
		// 	for (let key of keys) {
		// 		const jwtKey = await importJWK(key);
		// 		try {
		// 			await jwtVerify(token.value, jwtKey);
		// 			verified = true;
		// 			break;
		// 		} catch (error) {
		// 			jwtError = true;
		// 		}
		// 	}
		// 	if (jwtError) {
		// 		return internalServerError();
		// 	}
		// 	if (!verified) {
		// 		return forbidden();
		// 	}
		// 	return await forwardRequest(hostname, request); // Fixed this line
		// }
		//Check if the authType is opaque token
		if (authType === "type") {
			let applicationID: string = "";
			let keyId: string = "";
			let accID: string = "";
			let jsonValue;
			// if (request.headers.get("cf-connecting-ip") != null) {
			// 	let ip = request.headers.get("cf-connecting-ip") || "";
			// 	IPAdd = ipToDecimal(ip);
			// }

			if (token.data?.value) {
				jsonValue = JSON.parse(token.data.value);
				applicationID = jsonValue.appId;
				keyId = jsonValue.id;
				accID = jsonValue.accId;
			}
			if (applicationID != appID) {
				return unauthorized();
			}
			if (token.metadata) {
				if (!token.data?.metadata?.act) {
					return forbidden();
				}
				if (token.data?.metadata.exp && token.data?.metadata.exp < Date.now()) {
					return forbidden();
				}

				let rlObject = {
					limit: token.data.metadata.rl?.limit,
					timeWindow: token.data.metadata.rl?.timeWindow,
					remaining: 0,
				};
				if (token.metadata.rl != null) {
					const id = env.RATE_LIMITER.idFromName(token.value);
					const rateLimiter = env.RATE_LIMITER.get(id);
					const response = await rateLimiter.fetch(
						new Request(`https://ratelimiter?key=${token}`),
					);
					const jsonResponse: { remaining: number } = await response.json();
					rlObject.remaining = jsonResponse.remaining;
					if (response.status === 429) {
						await logKeyUsageEvent(
							{
								accID: accID,
								appID: applicationID,
								keyID: keyId,
								appName: token.metadata.name,
								userAgent: request.headers.get("user-agent") || "",
								ipAddress: IPAdd,
								success: verificationSuccess ? 1 : 0,
								metadata: {
									userAgent: request.headers.get("user-agent") || "",
									ipAddress: IPAdd,
								},
							},
							env,
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
					const response = await bucket.fetch(
						new Request(`https://remainer?key=${token}`),
					);
					const jsonResponse: { remaining: number } = await response.json();
					remaObject.remaining = jsonResponse.remaining;
					if (response.status === 200) {
						if (jsonResponse.remaining === 0) {
							token.metadata.act = false;
							jsonValue.enabled = false;
							await env.typeauth_keys.put(
								token.value,
								JSON.stringify(jsonValue),
								{ metadata: token.metadata },
							);
							const { success } = await env.DB.prepare(
								"UPDATE keys SET enabled = false WHERE id = ?1",
							)
								.bind({ keyId })
								.run();
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
								userAgent: request.headers.get("user-agent") || "",
								success: verificationSuccess ? 1 : 0,
								metadata: {
									userAgent: request.headers.get("user-agent") || "",
									ipAddress: IPAdd,
								},
							},
							env,
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
						userAgent: request.headers.get("user-agent") || "",
						success: verificationSuccess ? 1 : 0,
						metadata: {},
					},
					env,
				);

				await forwardRequest(hostname, request);
			}
		}
		console.log(token);

		return new Response("Hello World!");
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
		const key = searchParams.get("key");
		const init = searchParams.get("init");
		const set = searchParams.get("set");

		if (!key) {
			return new Response(JSON.stringify({ error: "Key is required" }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (init) {
			await this.state.storage.put(key, set);
			return new Response(JSON.stringify(set), {
				status: 201,
				headers: { "Content-Type": "application/json" },
			});
		}
		// Retrieve the key details from storage or database
		const keyDetails = await this.getKeyDetails(key);

		if (!keyDetails) {
			return new Response(JSON.stringify({ error: "Invalid key" }), {
				status: 401,
				headers: { "Content-Type": "application/json" },
			});
		}

		const { limit, timeWindow } = keyDetails.rl;

		const now = Date.now() / 1000; // Current timestamp in seconds

		const storageValue = await this.state.storage.get<{
			value: number;
			expiration: number;
		}>(key);
		let value = storageValue?.value || 0;
		let expiration = storageValue?.expiration || now + timeWindow;

		if (now < expiration) {
			if (value >= limit) {
				return new Response(
					JSON.stringify({ error: "Rate limit exceeded", remaining: 0 }),
					{
						status: 429,
						headers: { "Content-Type": "application/json" },
					},
				);
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
			headers: { "Content-Type": "application/json" },
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
		const key = searchParams.get("key");
		const set = searchParams.get("set");
		const init = searchParams.get("init");
		const get = searchParams.get("get");
		if (!key) {
			return new Response(JSON.stringify({ error: "Key is required" }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (get) {
			let remaining = await this.state.storage.get(key);
			return new Response(JSON.stringify({ remaining: remaining }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (init) {
			if (!set) {
				return new Response(JSON.stringify({ error: "set is missing" }), {
					status: 401,
					headers: { "Content-Type": "application/json" },
				});
			}
			await this.state.storage.put(key, parseInt(set));
			return new Response(JSON.stringify({ remaining: set }), {
				status: 201,
				headers: { "Content-Type": "application/json" },
			});
		}

		// Retrieve the key details from storage or database
		const keyDetails = await this.getKeyDetails(key);

		if (!keyDetails) {
			return new Response(JSON.stringify({ error: "Invalid key" }), {
				status: 401,
				headers: { "Content-Type": "application/json" },
			});
		}

		let remaining = await this.state.storage.get<number>(key);

		if (remaining === undefined) {
			return new Response(JSON.stringify({ error: "Invalid key" }), {
				status: 401,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (remaining <= 0) {
			return new Response(
				JSON.stringify({ error: "Usage limit exceeded", remaining: 0 }),
				{
					status: 429,
					headers: { "Content-Type": "application/json" },
				},
			);
		}

		await this.state.storage.put(key, remaining - 1);

		return new Response(JSON.stringify({ remaining: remaining - 1 }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
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
	const octets = ipAddress.split(".");

	// Validate the format (4 octets, each between 0 and 255)
	if (octets.length !== 4 || !octets.every((octet) => isValidOctet(octet))) {
		return 0;
	}

	// Convert each octet to a number and shift/add for final decimal value
	return octets.reduce((decimal, octet, index) => {
		const octetValue = Number.parseInt(octet, 10);
		return decimal + octetValue * (256 ** 3 - index);
	}, 0);
}

function isValidOctet(octet: string): boolean {
	const octetValue = Number.parseInt(octet, 10);
	return !Number.isNaN(octetValue) && octetValue >= 0 && octetValue <= 255;
}
