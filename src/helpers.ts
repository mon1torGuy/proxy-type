import type { KeyUsageEvent, KVMetadata } from "./types";

interface Env {
	typeauth_keys: KVNamespace;
	proxy_conf: KVNamespace;
	ANALYTICS: AnalyticsEngineDataset;
}

export function unauthorized(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Unauthorized" }),
		{
			status: 401,
			headers: { "Content-Type": "application/json" },
		},
	);
}
// create a helper function to response when the request is not found
export function notFound(): Response {
	return new Response(JSON.stringify({ success: true, message: "Not Found" }), {
		status: 404,
		headers: { "Content-Type": "application/json" },
	});
}

// create a helper function to response when the request is forbidden
export function forbidden(): Response {
	return new Response(JSON.stringify({ success: true, message: "Forbidden" }), {
		status: 403,
		headers: { "Content-Type": "application/json" },
	});
}
// create a helper function to response when the request is bad request
export function badRequest(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Bad Request" }),
		{
			status: 400,
			headers: { "Content-Type": "application/json" },
		},
	);
}

// create a helper function to response when the request is unacceptable
export function unacceptable(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Unacceptable" }),
		{
			status: 406,
			headers: { "Content-Type": "application/json" },
		},
	);
}

// create a helper function to response when the request is too long
export function tooLong(): Response {
	return new Response(JSON.stringify({ success: true, message: "Too Long" }), {
		status: 413,
		headers: { "Content-Type": "application/json" },
	});
}

// create a helper function to response when the request is too many requests
export function tooManyRequests(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Too Many Requests" }),
		{
			status: 429,
			headers: { "Content-Type": "application/json" },
		},
	);
}

// create a helper function to response when the request is internal server error
export function internalServerError(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Internal Server Error" }),
		{
			status: 500,
			headers: { "Content-Type": "application/json" },
		},
	);
}

// create a helper function to response when the request is service unavailable
export function serviceUnavailable(): Response {
	return new Response(
		JSON.stringify({ success: true, message: "Service Unavailable" }),
		{
			status: 503,
			headers: { "Content-Type": "application/json" },
		},
	);
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
		ipAddress,
		userAgent,
		eventType,
	} = event;
	env.ANALYTICS.writeDataPoint({
		blobs: [accID, appID, keyID, userAgent, appName, eventType],
		doubles: [success, ipAddress],
		indexes: [keyID],
	});
}

export function ipToDecimal(ipAddress: string): number {
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

export function isValidOctet(octet: string): boolean {
	const octetValue = Number.parseInt(octet, 10);
	return !Number.isNaN(octetValue) && octetValue >= 0 && octetValue <= 255;
}

export async function generateCacheKey(request: Request) {
	const url = new URL(request.url);

	const cacheKeyParts = [
		request.method,
		url.pathname,
		url.search, // Include query string
		request.headers.get("Authorization") || "",
	];

	// For PUT and POST requests, include a hash of the request body
	if (request.method === "PUT" || request.method === "POST") {
		const body = await request.clone().text();
		const bodyHash = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(body),
		);
		const hashArray = Array.from(new Uint8Array(bodyHash));
		const bodyHashHex = hashArray
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
		cacheKeyParts.push(bodyHashHex);
	}

	return new Request(cacheKeyParts.join("|"), {
		method: request.method,
		headers: request.headers,
	});
}

export async function handleAPICache(request: Request, ctx: ExecutionContext) {
	const cacheKey = await generateCacheKey(request);
	const cache = caches.default;

	// Try to get the response from cache
	let response = await cache.match(cacheKey);

	if (!response) {
		console.log(`Cache miss for: ${request.url}`);
		//@ts-expect-error
		response = await fetch(request);
		response = new Response(response?.body, response);
		response.headers.append("Cache-Control", "s-maxage=300");
		ctx.waitUntil(cache.put(cacheKey, response.clone()));
	}
	console.log(`Cache hit for: ${request.url}`);
	return response;
}
