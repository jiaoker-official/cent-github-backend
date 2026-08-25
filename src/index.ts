import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { cors } from "hono/cors";
import { isHttpOrHttpsRedirect, verifyRedirectSign } from "./lib/sign_verify";
import { encodeState, decodeState } from "./lib/state";
import white_list from "./white_list";
import proxyRouter from "./routes/proxy";
import currencyRouter from "./routes/currency";

/**
 * 定义 Cloudflare Worker 的环境变量类型
 */
type Bindings = {
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;
	// Gitee (码云) OAuth
	GITEE_CLIENT_ID: string;
	GITEE_CLIENT_SECRET: string;
	/** 非 http(s) redirect_uri 时 authorize 查询参数 sign 的 AES-GCM 密钥 */
	SIGN_SECRETS?: string;
	ENCRYPTION_SECRETS?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use(
	"*",
	cors({
		origin: white_list,
		allowMethods: [
			"GET",
			"POST",
			"PUT",
			"DELETE",
			"PATCH",
			"OPTIONS",
			"HEAD",
			"PROPFIND",
			"PROPPATCH",
			"MKCOL",
			"COPY",
			"MOVE",
			"LOCK",
			"UNLOCK",
			"TRACE",
			"CONNECT",
		],
		allowHeaders: [
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			"Depth",
			"Destination",
			"If",
			"Accept-Encoding",
		],
		maxAge: 86400,
	}),
);

// --- 配置常量 ---
const GITHUB_APP_SLUG = "cent-accounting";

const INVALID_REDIRECT_MSG =
	"redirect url not valid, see https://github.com/glink25/github-login?tab=readme-ov-file#%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8";

const isValidRedirect = (url: string) => {
	return white_list.some((v) => url.startsWith(v));
};

/**
 * 安全获取 Gitee Client Secret（多途径兜底探测）
 */
function getGiteeSecret(c: any): string {
	if (c.env && c.env.GITEE_CLIENT_SECRET) return c.env.GITEE_CLIENT_SECRET;
	if (typeof process !== "undefined" && process.env && process.env.GITEE_CLIENT_SECRET) return process.env.GITEE_CLIENT_SECRET;
	if ((globalThis as any).GITEE_CLIENT_SECRET) return (globalThis as any).GITEE_CLIENT_SECRET;
	return "";
}

/**
 * 路由 1: /api/github-oauth/authorize
 */
app.get("/api/github-oauth/authorize", async (c) => {
	const env = c.env as Record<string, string>;
	const { redirect_uri: appReturnUrl } = c.req.query();
	if (!appReturnUrl) {
		c.status(400);
		return c.json({ error: "`redirect_uri` is required." });
	}
	if (!isValidRedirect(appReturnUrl)) {
		c.status(400);
		return c.json({ error: INVALID_REDIRECT_MSG });
	}
	if (!isHttpOrHttpsRedirect(appReturnUrl)) {
		const signSecret = c.env.SIGN_SECRETS?.trim();
		if (!signSecret) {
			c.status(500);
			return c.json({ error: "SIGN_SECRETS is not configured." });
		}
		try {
			await verifyRedirectSign(c.req.query("sign"), signSecret);
		} catch (err: any) {
			c.status(400);
			console.error("[verifyRedirectSign]:", err.message);
			return c.json({ error: err.message });
		}
	}
	const statePayload = appReturnUrl;
	const state = await encodeState(statePayload, env.ENCRYPTION_SECRETS);

	const authUrl = new URL("https://github.com/login/oauth/authorize");
	authUrl.searchParams.set("client_id", c.env.GITHUB_CLIENT_ID);
	authUrl.searchParams.set("state", state);

	console.log("Redirecting user to GitHub for authorization...");
	return c.redirect(authUrl.toString());
});

/**
 * 路由 2: /api/github-oauth/authorized
 */
app.get("/api/github-oauth/authorized", async (c) => {
	const env = c.env as Record<string, string>;
	const code = c.req.query("code");
	const state = c.req.query("state");
	if (!code || !state) {
		throw new HTTPException(400, {
			message: 'Missing "code" or "state" query parameter.',
		});
	}
	let appReturnUrl: string;
	try {
		appReturnUrl = await decodeState(state, env.ENCRYPTION_SECRETS);
		console.log("State validation successful.");
	} catch (err: any) {
		console.error("Invalid state received:", err);
		throw new HTTPException(400, { message: err.message });
	}

	if (!isValidRedirect(appReturnUrl)) {
		throw new HTTPException(400, { message: INVALID_REDIRECT_MSG });
	}
	const returnUrl = new URL(appReturnUrl);

	console.log("Exchanging code for access token...");
	const tokenResponse = await fetch(
		"https://github.com/login/oauth/access_token",
		{
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
			},
			body: JSON.stringify({
				client_id: c.env.GITHUB_CLIENT_ID,
				client_secret: c.env.GITHUB_CLIENT_SECRET,
				code: code,
			}),
		},
	);

	if (!tokenResponse.ok) {
		const errorBody = await tokenResponse.text();
		console.error("Failed to get access token:", errorBody);
		throw new HTTPException(500, {
			message: "Failed to exchange code for access token.",
		});
	}

	const tokenData = (await tokenResponse.json()) as {
		access_token?: string;
		error?: string;
	};

	if (tokenData.error || !tokenData.access_token) {
		console.error("Error in token response from GitHub:", tokenData);
		throw new HTTPException(400, {
			message: `GitHub returned an error: ${tokenData.error}`,
		});
	}

	const accessToken = tokenData.access_token;
	console.log("Successfully obtained access token.");

	console.log("Checking user installation status...");
	const installationsResponse = await fetch(
		"https://api.github.com/user/installations",
		{
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: "application/vnd.github.v3+json",
				"User-Agent": `${GITHUB_APP_SLUG} (Cloudflare Worker)`,
			},
		},
	);

	if (!installationsResponse.ok) {
		const errorBody = await installationsResponse.text();
		console.error("Failed to fetch user installations:", errorBody);
		throw new HTTPException(500, {
			message: "Failed to check app installation status.",
		});
	}

	const installationsData = (await installationsResponse.json()) as {
		total_count: number;
		installations: any[];
	};

	if (
		installationsData.total_count > 0 &&
		installationsData.installations.length > 0
	) {
		console.log("User has installed the app. Redirecting to dashboard.");
		const redirectUrl = returnUrl;
		redirectUrl.searchParams.set(
			"github_authorized",
			JSON.stringify(tokenData),
		);
		return c.redirect(redirectUrl.toString());
	} else {
		console.log(
			"User has not installed the app. Redirecting to installation page.",
		);
		const installUrl = new URL(
			`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`,
		);
		installUrl.searchParams.set("state", state);
		return c.redirect(installUrl);
	}
});

/**
 * 路由 3: /api/github-oauth/refresh-token
 */
app.post("/api/github-oauth/refresh-token", async (c) => {
	const body = await c.req.json();
	const refreshToken = body.refreshToken;
	if (!refreshToken) {
		throw new HTTPException(500, {
			message: "invalid refresh token.",
		});
	}
	const tokenResponse = await fetch(
		"https://github.com/login/oauth/access_token",
		{
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
			},
			body: JSON.stringify({
				client_id: c.env.GITHUB_CLIENT_ID,
				client_secret: c.env.GITHUB_CLIENT_SECRET,
				grant_type: "refresh_token",
				refresh_token: refreshToken,
			}),
		},
	);
	if (!tokenResponse.ok) {
		const errorBody = await tokenResponse.text();
		console.error("Failed to get access token:", errorBody);
		throw new HTTPException(500, {
			message: "Failed to exchange code for access token.",
		});
	}

	const tokenData = (await tokenResponse.json()) as {
		access_token?: string;
		error?: string;
	};

	if (tokenData.error || !tokenData.access_token) {
		console.error("Error in token response from GitHub:", tokenData);
		throw new HTTPException(400, {
			message: `GitHub returned an error: ${tokenData.error}`,
		});
	}
	return c.json(tokenData);
});

// ==========================================
// Gitee 授权相关路由
// ==========================================

app.get("/api/gitee-oauth/authorize", async (c) => {
	const env = c.env as Record<string, string>;
	const { redirect_uri: appReturnUrl } = c.req.query();
	if (!appReturnUrl) {
		c.status(400);
		return c.json({ error: "`redirect_uri` is required." });
	}
	if (!isValidRedirect(appReturnUrl)) {
		c.status(400);
		return c.json({ error: INVALID_REDIRECT_MSG });
	}
	if (!isHttpOrHttpsRedirect(appReturnUrl)) {
		const signSecret = c.env.SIGN_SECRETS?.trim();
		if (!signSecret) {
			c.status(500);
			return c.json({ error: "SIGN_SECRETS is not configured." });
		}
		try {
			await verifyRedirectSign(c.req.query("sign"), signSecret);
		} catch (err: any) {
			c.status(400);
			return c.json({ error: err.message });
		}
	}

	const statePayload = appReturnUrl;
	const state = await encodeState(statePayload, env.ENCRYPTION_SECRETS);

	const origin = new URL(c.req.url).origin;
	const callback = `${origin}/api/gitee-oauth/authorized`;

	const authUrl = new URL("https://gitee.com/oauth/authorize");
	authUrl.searchParams.set("client_id", c.env.GITEE_CLIENT_ID);
	authUrl.searchParams.set("redirect_uri", callback);
	authUrl.searchParams.set("response_type", "code");
	authUrl.searchParams.set("state", state);

	console.log(
		"Redirecting user to Gitee for authorization...",
		authUrl.toString(),
	);
	return c.redirect(authUrl.toString());
});

app.get("/api/gitee-oauth/authorized", async (c) => {
	const env = c.env as Record<string, string>;
	const code = c.req.query("code");
	const state = c.req.query("state");
	if (!code || !state) {
		throw new HTTPException(400, {
			message: 'Missing "code" or "state" query parameter.',
		});
	}

	let appReturnUrl: string;
	try {
		appReturnUrl = await decodeState(state, env.ENCRYPTION_SECRETS);
		console.log("Gitee state validation successful.");
	} catch (err: any) {
		console.error("Invalid state received from Gitee:", err);
		throw new HTTPException(400, { message: err.message });
	}

	if (!isValidRedirect(appReturnUrl)) {
		throw new HTTPException(400, { message: INVALID_REDIRECT_MSG });
	}

	const origin = new URL(c.req.url).origin;
	const callback = `${origin}/api/gitee-oauth/authorized`;

	// 多途径读取 Secret
	const giteeSecret = getGiteeSecret(c);

	// 打印安全调试日志（只有长度和前缀，不暴露完整密钥）
	console.log("Debug Client ID:", c.env.GITEE_CLIENT_ID);
	console.log("Debug Secret Length:", giteeSecret ? giteeSecret.length : 0);
	console.log(
		"Debug Secret Preview:",
		giteeSecret ? giteeSecret.substring(0, 3) + "***" : "MISSING/EMPTY"
	);

	const params = new URLSearchParams({
		grant_type: "authorization_code",
		code: code,
		client_id: c.env.GITEE_CLIENT_ID,
		client_secret: giteeSecret,
		redirect_uri: callback,
	});

	console.log("Exchanging code for Gitee access token...");
	const tokenResponse = await fetch("https://gitee.com/oauth/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
			"User-Agent": "Cent-App (Cloudflare Worker)", // 补充 User-Agent
		},
		body: params.toString(),
	});

	if (!tokenResponse.ok) {
		const errorBody = await tokenResponse.text();
		console.error("Failed to get Gitee access token:", errorBody);
		throw new HTTPException(500, {
			message: "Failed to exchange code for access token (Gitee).",
		});
	}

	const tokenData = await tokenResponse.json();
	if ((tokenData as any).error || !(tokenData as any).access_token) {
		console.error("Error in Gitee token response:", tokenData);
		throw new HTTPException(400, {
			message: `Gitee returned an error: ${(tokenData as any).error}`,
		});
	}

	const returnUrl = new URL(appReturnUrl);
	returnUrl.searchParams.set("gitee_authorized", JSON.stringify(tokenData));
	return c.redirect(returnUrl.toString());
});

app.post("/api/gitee-oauth/refresh-token", async (c) => {
	const body = await c.req.json();
	const refreshToken = body.refreshToken;
	if (!refreshToken) {
		throw new HTTPException(400, {
			message: "invalid refresh token.",
		});
	}

	const giteeSecret = getGiteeSecret(c);

	const params = new URLSearchParams({
		grant_type: "refresh_token",
		refresh_token: refreshToken,
		client_id: c.env.GITEE_CLIENT_ID,
		client_secret: giteeSecret,
	});

	const tokenResponse = await fetch("https://gitee.com/oauth/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
			"User-Agent": "Cent-App (Cloudflare Worker)",
		},
		body: params.toString(),
	});

	if (!tokenResponse.ok) {
		const errorBody = await tokenResponse.text();
		console.error("Failed to refresh Gitee token:", errorBody);
		throw new HTTPException(500, {
			message: "Failed to refresh access token (Gitee).",
		});
	}

	const tokenData = await tokenResponse.json();
	if ((tokenData as any).error || !(tokenData as any).access_token) {
		console.error("Error in Gitee refresh response:", tokenData);
		throw new HTTPException(400, {
			message: `Gitee returned an error: ${(tokenData as any).error}`,
		});
	}

	return c.json(tokenData as any);
});

app.route("", currencyRouter);

export default app;
