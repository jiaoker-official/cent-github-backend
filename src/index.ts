// 我正在使用cloudflare workers部署一个用户 github app 授权服务端流程，使用 nodejs和hono编写，假设目标环境已经包含如下环境变量：
// ```env
// GITHUB_CLIENT_SECRET=xxx
// GITHUB_CLIENT_ID=xxx
// ```

// ```typescript
// function encodeState(value: string): Promise<string>

// function decodeState(encryptedState: string): Promise<string>

// ```
// 并且提供了简易的加密方法 decodeState, encodeState ，请根据如下流程编写可用的授权程序，实现如下核心的登录接口：
// ```typescript
// app.get("/api/github-oauth/authorize")
// app.get("/api/github-oauth/authorized")
// ```

// 核心流程如下：
// 核心 GitHub App 登录/安装分流流程（Prompt 格式）
// 目标： 在用户登录时，通过服务器端点判断其 GitHub App 安装状态，实现新老用户分流。

// 核心流程提示词：

// 模式： GitHub App 授权/安装分流（服务器控制）

// 前置配置：

// GitHub App 授权回调 URL (Callback URL) = 服务器端点 (/api/github-oauth/authorized)。

// 取消勾选“安装时请求用户授权”。

// 步骤：

// 统一入口： 用户从客户端访问 (/api/github-oauth/authorize) 跳转至 GitHub OAuth 授权 URL (github.com/login/oauth/authorize)。

// 授权回调 (服务器端)： GitHub 重定向到服务器端点 (/api/github-oauth/authorized)，附带 code。

// 服务器操作（双重检查）： a. 获取 Token： 服务器使用 code 和保密的 client_secret 交换 User Access Token。 b. 检查安装： 服务器使用该 User Access Token 调用 GitHub API (/user/installations) 检查 App 是否已安装。

// 智能分流重定向：

// If 已安装 (老用户)： 服务器将 User Access Token 传给客户端，并重定向到应用首页 AFTER_LOGIN_URL。

// If 未安装 (新用户)： 服务器 302 重定向到 App 安装 URL (/apps/YOUR-APP-SLUG/installations/new)。

// 后续登录： 无论是分流后的首页还是完成安装后的重定向，客户端均使用获得的 User Access Token 建立前端会话。

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { cors } from "hono/cors";
import { isHttpOrHttpsRedirect, verifyRedirectSign } from "./lib/sign_verify";
import { encodeState, decodeState } from "./lib/state";
import white_list from "./white_list";
import proxyRouter from "./routes/proxy";
import currencyRouter from "./routes/currency";

/**
 * 定义 Cloudflare Worker 的环境变量类型，确保类型安全。
 * 在 Cloudflare 控制台中必须设置 GITHUB_CLIENT_ID 和 GITHUB_CLIENT_SECRET。
 */
type Bindings = {
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;
	// Gitee (码云) OAuth
	GITEE_CLIENT_ID: string;
	GITEE_CLIENT_SECRET: string;
	/** 非 http(s) redirect_uri 时 authorize 查询参数 sign 的 AES-GCM 密钥；生产环境用 wrangler secret put SIGN_SECRETS */
	SIGN_SECRETS?: string;
	// 如果使用 Worker KV 或其他绑定，请在此处添加
};

const app = new Hono<{ Bindings: Bindings }>();
app.use(
	"*",
	cors({
		// 允许所有来源访问，这是实现 CORS 绕过的关键
		origin: white_list,
		// 允许所有常见的 HTTP 方法
		allowMethods: [
			"GET",
			"POST",
			"PUT",
			"DELETE",
			"PATCH",
			"OPTIONS",
			"HEAD",
			// WebDAV 方法：
			"PROPFIND",
			"PROPPATCH",
			"MKCOL",
			"COPY",
			"MOVE",
			"LOCK",
			"UNLOCK",
			// 其他不常见但可能用到的方法：
			"TRACE",
			"CONNECT",
		],
		// 允许所有常见的请求头部
		// **关键修改点：确保 WebDAV 头部 'Depth' (以及 'Destination', 'If' 等) 被明确允许**
		allowHeaders: [
			// 标准头部
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			// WebDAV 头部
			"Depth",
			"Destination",
			"If",
			"Accept-Encoding",
			// 建议：如果 WebDAV 客户端使用了其他自定义头部，也需要添加
		],
		// 浏览器缓存 CORS 预检结果的时间（秒）
		maxAge: 86400, // 24小时
	}),
);

// --- 配置常量 ---
// 警告：请务必将下面的值替换为您自己的 GitHub App 的实际信息！
const GITHUB_APP_SLUG = "cent-accounting";

const INVALID_REDIRECT_MSG =
	"redirect url not valid, see https://github.com/glink25/github-login?tab=readme-ov-file#%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8";
const isValidRedirect = (url: string) => {
	return white_list.some((v) => url.startsWith(v));
};

/**
 * 路由 1: /api/github-oauth/authorize
 * 描述: 这是用户授权的统一入口点。
 * 流程:
 * 1. 创建一个唯一的 state 值以防止 CSRF 攻击。
 * 2. 将 state 加密。
 * 3. 构建 GitHub OAuth URL 并将用户重定向过去。
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
	// GitHub App 规范要求 redirect_uri 在这里不是必须的，它会使用 App 设置中配置的回调 URL
	// authUrl.searchParams.set('redirect_uri', 'YOUR_CALLBACK_URL');
	authUrl.searchParams.set("state", state);
	// 对于检查安装状态，不需要特殊 scope，登录即可
	// authUrl.searchParams.set('scope', 'read:user');

	console.log("Redirecting user to GitHub for authorization...");
	return c.redirect(authUrl.toString());
});

/**
 * 路由 2: /api/github-oauth/authorized
 * 描述: 这是 GitHub 授权后的回调地址。
 * 流程:
 * 1. 从查询参数中获取 code 和 state。
 * 2. 验证 state 的有效性。
 * 3. 使用 code 向 GitHub 交换 User Access Token。
 * 4. 使用 Token 调用 GitHub API 检查用户是否已安装该 App。
 * 5. 根据安装状态，将用户智能分流到“应用首页”或“App 安装页”。
 */
app.get("/api/github-oauth/authorized", async (c) => {
	const env = c.env as Record<string, string>;
	const code = c.req.query("code");
	const state = c.req.query("state");
	// 步骤 1: 验证参数
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

	// 步骤 3: 使用 code 交换 Access Token
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

	// 步骤 4: 检查用户 App 安装状态
	console.log("Checking user installation status...");
	const installationsResponse = await fetch(
		"https://api.github.com/user/installations",
		{
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: "application/vnd.github.v3+json",
				"User-Agent": `${GITHUB_APP_SLUG} (Cloudflare Worker)`, // 推荐设置 User-Agent
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

	// 步骤 5: 智能分流
	if (
		installationsData.total_count > 0 &&
		installationsData.installations.length > 0
	) {
		// 情况 A: 已安装 App (老用户)
		console.log("User has installed the app. Redirecting to dashboard.");
		const redirectUrl = returnUrl;
		// 将 token 作为参数传递给前端，前端需要实现接收逻辑
		redirectUrl.searchParams.set(
			"github_authorized",
			JSON.stringify(tokenData),
		);
		return c.redirect(redirectUrl.toString());
	} else {
		// 情况 B: 未安装 App (新用户)
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
 * 刷新 github token
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

// 2. gitee 授权相关
// 基于 Gitee (码云) 的 OAuth2 实现，流程与上面的 GitHub 类似：
// 1) /api/gitee-oauth/authorize - 统一入口，生成 state 并重定向到 gitee 授权页
// 2) /api/gitee-oauth/authorized - 授权回调，使用 code 交换 access_token 并将结果重定向回客户端
// 3) /api/gitee-oauth/refresh-token - 使用 refresh_token 刷新 access_token

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

	// 回调地址：使用当前 worker 的 origin + 回调路径
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

	// 交换 access_token
	const origin = new URL(c.req.url).origin;
	const callback = `${origin}/api/gitee-oauth/authorized`;

	const params = new URLSearchParams({
		grant_type: "authorization_code",
		code: code,
		client_id: c.env.GITEE_CLIENT_ID,
		client_secret: c.env.GITEE_CLIENT_SECRET,
		redirect_uri: callback,
	});

	console.log("Exchanging code for Gitee access token...");
	const tokenResponse = await fetch("https://gitee.com/oauth/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
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

	// 将 token 信息带回前端
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

	const params = new URLSearchParams({
		grant_type: "refresh_token",
		refresh_token: refreshToken,
		client_id: c.env.GITEE_CLIENT_ID,
		client_secret: c.env.GITEE_CLIENT_SECRET,
	});

	const tokenResponse = await fetch("https://gitee.com/oauth/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
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

// 注册子路由
// app.route("", proxyRouter);
app.route("", currencyRouter);

export default app;
