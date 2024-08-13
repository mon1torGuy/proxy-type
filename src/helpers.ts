import type { KeyUsageEvent, KVMetadata } from "./types";

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

export function unauthorized(): Response {
	return new Response("Unauthorized", {
		status: 401,
	});
}
// create a helper function to response when the request is not found
export function notFound(): Response {
	return new Response("Not Found", {
		status: 404,
	});
}

// create a helper function to response when the request is forbidden
export function forbidden(): Response {
	return new Response("Forbidden", {
		status: 403,
	});
}
// create a helper function to response when the request is bad request
export function badRequest(): Response {
	return new Response("Bad Request", {
		status: 400,
	});
}

// create a helper function to response when the request is unacceptable
export function unacceptable(): Response {
	return new Response("Unacceptable", {
		status: 406,
	});
}

// create a helper function to response when the request is too long
export function tooLong(): Response {
	return new Response("Too Long", {
		status: 413,
	});
}

// create a helper function to response when the request is too many requests
export function tooManyRequests(): Response {
	return new Response("Too Many Requests", {
		status: 429,
	});
}

// create a helper function to response when the request is internal server error
export function internalServerError(): Response {
	return new Response("Internal Server Error", {
		status: 500,
	});
}

// create a helper function to response when the request is service unavailable
export function serviceUnavailable(): Response {
	return new Response("Service Unavailable", {
		status: 503,
	});
}

// Helper function to get the Authorization header
export async function getAuthHeader(
	headerName: string,
	request: Request,
	authType: string,
	env: Env,
): Promise<{
	success: boolean;
	message: string;
	data: { value: string; metadata: KVMetadata | null } | null;
}> {
	const authHeader = request.headers.get(headerName);
	if (!authHeader || authHeader === undefined) {
		return { success: false, message: "No Authorization header", data: null };
	}
	const [type, key] = authHeader.split(" ");

	if (type !== "Bearer") {
		return { success: false, message: "Not a Bearer token", data: null };
	}
	if (authType === "jwt") {
		return {
			success: true,
			message: "Success JWT",
			data: { value: key, metadata: null },
		};
	}
	const { value, metadata } =
		await env.typeauth_keys.getWithMetadata<KVMetadata>(key);
	if (!value) {
		return { success: false, message: "No value", data: null };
	}
	if (!metadata) {
		return { success: false, message: "No metadata", data: null };
	}
	return { success: true, message: "Success", data: { value, metadata } };
}

//create a helper function that take a hostname and a request and forward the request to the backend
export async function forwardRequest(
	hostname: string,
	request: Request,
): Promise<Response> {
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

export async function logKeyUsageEvent(
	event: KeyUsageEvent,
	env: Env,
): Promise<void> {
	const {
		accID,
		appID,
		appName,
		keyID,
		success,
		metadata,
		ipAddress,
		userAgent,
	} = event;
	env.ANALYTICS.writeDataPoint({
		blobs: [accID, appID, keyID, userAgent, appName],
		doubles: [success, ipAddress],
		indexes: [keyID],
	});
}
