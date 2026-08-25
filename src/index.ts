// 我正在使用cloudflare workers部署一个用户 github app 授权服务端流程，使用 nodejs和hono编写，假设目标环境已经包含如下环境变量：
// ```env
// GITHUB_CLIENT_SECRET=xxx
// GITHUB_CLIENT_ID=xxx
// ```
//
// ```typescript
// function encodeState(value: string): Promise<string>
//
// function decodeState(encryptedState: string): Promise<string>
// ```
//
// 并且提供了简易的加密方法 decodeState, encodeState ，请根据如下流程编写可用的授权程序，实现如下核心的登录接口：
//
// ```typescript
// app.get("/api/github-oauth/authorize")
// app.get("/api/github-oauth/authorized")
// ```
//
// 核心流程如下：
// 核心 GitHub App 登录/安装分流流程（Prompt 格式）
// 目标： 在用户登录时，通过服务器端点判断其 GitHub App 安装状态，实现新老用户分流。
//
// 核心流程提示词：
//
// 模式： GitHub App 授权/安装分流（服务器控制）
//
// 前置配置：
// GitHub App 授权回调 URL (Callback URL) = 服务器端点 (/api/github-oauth/authorized)。
//
// 取消勾选“安装时请求用户授权”。
//
// 步骤：
// 统一入口： 用户从客户端访问 (/api/github-oauth/authorize) 跳转至 GitHub OAuth 授权 URL (github.com/login/oauth/authorize)。
//
// 授权回调 (服务器端)： GitHub 重定向到服务器端点 (/api/github-oauth/authorized)，附带 code。
// 服务器操作（双重检查）：
// a. 获取 Token： 服务器使用 code 和保密的 client_secret 交换 User Access Token。
// b. 检查安装： 服务器使用该 User Access Token 调用 GitHub API (/user/installations) 检查 App 是否已安装。
//
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
 *
 * Cloudflare 控制台中需要配置：
 *
 * GITHUB_CLIENT_ID
 * GITHUB_CLIENT_SECRET
 * GITEE_CLIENT_ID
 * GITEE_CLIENT_SECRET
 *
 * ENCRYPTION_SECRETS 用于 state 加密。
 */
type Bindings = {
	GITHUB_CLIENT_ID: string;
	GITHUB_CLIENT_SECRET: string;

	// Gitee (码云) OAuth
	GITEE_CLIENT_ID: string;
	GITEE_CLIENT_SECRET: string;

	/** 非 http(s) redirect_uri 时 authorize 查询参数 sign 的 AES-GCM 密钥 */
	SIGN_SECRETS?: string;

	/** OAuth state 加密密钥 */
	ENCRYPTION_SECRETS: string;

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

			// WebDAV 方法
			"PROPFIND",
			"PROPPATCH",
			"MKCOL",
			"COPY",
			"MOVE",
			"LOCK",
			"UNLOCK",

			// 其他方法
			"TRACE",
			"CONNECT",
		],

		// 允许所有常见的请求头部
		allowHeaders: [
			"Content-Type",
			"Authorization",
			"X-Requested-With",

			// WebDAV 头部
			"Depth",
			"Destination",
			"If",
			"Accept-Encoding",
		],

		// 浏览器缓存 CORS 预检结果的时间
		maxAge: 86400,
	}),
);

// ------------------------------------------------------------
// 配置常量
// ------------------------------------------------------------

const GITHUB_APP_SLUG = "cent-accounting";

const INVALID_REDIRECT_MSG =
	"redirect url not valid, see https://github.com/glink25/github-login?tab=readme-ov-file#%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8";

/**
 * 判断 redirect_uri 是否在白名单中。
 */
const isValidRedirect = (url: string) => {
	return white_list.some((v) => url.startsWith(v));
};

/**
 * 安全显示 Client ID。
 *
 * 绝对不要把完整 Client Secret 写入日志。
 */
const maskClientId = (clientId: string | undefined) => {
	if (!clientId) {
		return null;
	}

	const value = clientId.trim();

	if (value.length <= 8) {
		return `${value.slice(0, 2)}...`;
	}

	return `${value.slice(0, 4)}...${value.slice(-4)}`;
};

/**
 * ------------------------------------------------------------
 * 临时 Gitee 配置调试接口
 * ------------------------------------------------------------
 *
 * 用于确认 Cloudflare Worker 运行时是否真的读取到了：
 *
 * GITEE_CLIENT_ID
 * GITEE_CLIENT_SECRET
 *
 * 访问：
 *
 * https://你的worker域名/api/debug-gitee
 *
 * 注意：
 * 这个接口只用于排查问题。
 * 问题解决以后建议删除。
 */
app.get("/api/debug-gitee", (c) => {
	const rawClientId = c.env.GITEE_CLIENT_ID;
	const rawClientSecret = c.env.GITEE_CLIENT_SECRET;

	const clientId = rawClientId?.trim();
	const clientSecret = rawClientSecret?.trim();

	return c.json({
		ok: true,

		gitee: {
			clientIdExists: !!clientId,
			clientIdLength: clientId?.length ?? 0,
			clientIdPreview: maskClientId(clientId),

			clientSecretExists: !!clientSecret,
			clientSecretLength: clientSecret?.length ?? 0,

			// 如果原始值存在前后空白，说明 Cloudflare 中保存的 Secret
			// 可能存在复制时产生的空格或换行。
			clientIdHasLeadingOrTrailingWhitespace:
				!!rawClientId && rawClientId !== rawClientId.trim(),

			clientSecretHasLeadingOrTrailingWhitespace:
				!!rawClientSecret && rawClientSecret !== rawClientSecret.trim(),
		},

		worker: {
			origin: new URL(c.req.url).origin,
			giteeCallback: `${
				new URL(c.req.url).origin
			}/api/gitee-oauth/authorized`,
		},
	});
});

/**
 * ------------------------------------------------------------
 * GitHub OAuth
 * ------------------------------------------------------------
 */

/**
 * 路由 1:
 *
 * /api/github-oauth/authorize
 *
 * 描述：
 * 这是用户授权的统一入口点。
 */
app.get("/api/github-oauth/authorize", async (c) => {
	const env = c.env as Record<string, string>;

	const { redirect_uri: appReturnUrl } = c.req.query();

	if (!appReturnUrl) {
		c.status(400);
		return c.json({
			error: "`redirect_uri` is required.",
		});
	}

	if (!isValidRedirect(appReturnUrl)) {
		c.status(400);
		return c.json({
			error: INVALID_REDIRECT_MSG,
		});
	}

	if (!isHttpOrHttpsRedirect(appReturnUrl)) {
		const signSecret = c.env.SIGN_SECRETS?.trim();

		if (!signSecret) {
			c.status(500);
			return c.json({
				error: "SIGN_SECRETS is not configured.",
			});
		}

		try {
			await verifyRedirectSign(
				c.req.query("sign"),
				signSecret,
			);
		} catch (err: any) {
			c.status(400);

			console.error(
				"[verifyRedirectSign]:",
				err.message,
			);

			return c.json({
				error: err.message,
			});
		}
	}

	const statePayload = appReturnUrl;

	const state = await encodeState(
		statePayload,
		env.ENCRYPTION_SECRETS,
	);

	const authUrl = new URL(
		"https://github.com/login/oauth/authorize",
	);

	authUrl.searchParams.set(
		"client_id",
		c.env.GITHUB_CLIENT_ID,
	);

	authUrl.searchParams.set("state", state);

	console.log(
		"Redirecting user to GitHub for authorization...",
	);

	return c.redirect(authUrl.toString());
});

/**
 * GitHub OAuth callback
 */
app.get("/api/github-oauth/authorized", async (c) => {
	const env = c.env as Record<string, string>;

	const code = c.req.query("code");
	const state = c.req.query("state");

	if (!code || !state) {
		throw new HTTPException(400, {
			message:
				'Missing "code" or "state" query parameter.',
		});
	}

	let appReturnUrl: string;

	try {
		appReturnUrl = await decodeState(
			state,
			env.ENCRYPTION_SECRETS,
		);

		console.log(
			"State validation successful.",
		);
	} catch (err: any) {
		console.error(
			"Invalid state received:",
			err,
		);

		throw new HTTPException(400, {
			message: err.message,
		});
	}

	if (!isValidRedirect(appReturnUrl)) {
		throw new HTTPException(400, {
			message: INVALID_REDIRECT_MSG,
		});
	}

	const returnUrl = new URL(appReturnUrl);

	console.log(
		"Exchanging code for GitHub access token...",
	);

	const githubClientId =
		c.env.GITHUB_CLIENT_ID?.trim();

	const githubClientSecret =
		c.env.GITHUB_CLIENT_SECRET?.trim();

	const tokenResponse = await fetch(
		"https://github.com/login/oauth/access_token",
		{
			method: "POST",

			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
			},

			body: JSON.stringify({
				client_id: githubClientId,
				client_secret: githubClientSecret,
				code: code,
			}),
		},
	);

	if (!tokenResponse.ok) {
		const errorBody =
			await tokenResponse.text();

		console.error(
			"Failed to get GitHub access token:",
			errorBody,
		);

		throw new HTTPException(500, {
			message:
				"Failed to exchange code for access token.",
		});
	}

	const tokenData =
		(await tokenResponse.json()) as {
			access_token?: string;
			error?: string;
		};

	if (
		tokenData.error ||
		!tokenData.access_token
	) {
		console.error(
			"Error in token response from GitHub:",
			tokenData,
		);

		throw new HTTPException(400, {
			message: `GitHub returned an error: ${tokenData.error}`,
		});
	}

	const accessToken =
		tokenData.access_token;

	console.log(
		"Successfully obtained GitHub access token.",
	);

	/**
	 * 检查用户 App 安装状态
	 */
	console.log(
		"Checking user installation status...",
	);

	const installationsResponse =
		await fetch(
			"https://api.github.com/user/installations",
			{
				headers: {
					Authorization: `Bearer ${accessToken}`,
					Accept:
						"application/vnd.github.v3+json",
					"User-Agent":
						`${GITHUB_APP_SLUG} (Cloudflare Worker)`,
				},
			},
		);

	if (!installationsResponse.ok) {
		const errorBody =
			await installationsResponse.text();

		console.error(
			"Failed to fetch user installations:",
			errorBody,
		);

		throw new HTTPException(500, {
			message:
				"Failed to check app installation status.",
		});
	}

	const installationsData =
		(await installationsResponse.json()) as {
			total_count: number;
			installations: any[];
		};

	/**
	 * 智能分流
	 */
	if (
		installationsData.total_count > 0 &&
		installationsData.installations.length > 0
	) {
		console.log(
			"User has installed the app. Redirecting to dashboard.",
		);

		const redirectUrl = returnUrl;

		redirectUrl.searchParams.set(
			"github_authorized",
			JSON.stringify(tokenData),
		);

		return c.redirect(
			redirectUrl.toString(),
		);
	} else {
		console.log(
			"User has not installed the app. Redirecting to installation page.",
		);

		const installUrl = new URL(
			`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`,
		);

		installUrl.searchParams.set(
			"state",
			state,
		);

		return c.redirect(
			installUrl.toString(),
		);
	}
});

/**
 * 刷新 GitHub token
 */
app.post(
	"/api/github-oauth/refresh-token",
	async (c) => {
		const body = await c.req.json();

		const refreshToken =
			body.refreshToken;

		if (!refreshToken) {
			throw new HTTPException(500, {
				message:
					"invalid refresh token.",
			});
		}

		const githubClientId =
			c.env.GITHUB_CLIENT_ID?.trim();

		const githubClientSecret =
			c.env.GITHUB_CLIENT_SECRET?.trim();

		const tokenResponse = await fetch(
			"https://github.com/login/oauth/access_token",
			{
				method: "POST",

				headers: {
					"Content-Type":
						"application/json",
					Accept: "application/json",
				},

				body: JSON.stringify({
					client_id:
						githubClientId,
					client_secret:
						githubClientSecret,
					grant_type:
						"refresh_token",
					refresh_token:
						refreshToken,
				}),
			},
		);

		if (!tokenResponse.ok) {
			const errorBody =
				await tokenResponse.text();

			console.error(
				"Failed to get GitHub access token:",
				errorBody,
			);

			throw new HTTPException(500, {
				message:
					"Failed to exchange code for access token.",
			});
		}

		const tokenData =
			(await tokenResponse.json()) as {
				access_token?: string;
				error?: string;
			};

		if (
			tokenData.error ||
			!tokenData.access_token
		) {
			console.error(
				"Error in token response from GitHub:",
				tokenData,
			);

			throw new HTTPException(400, {
				message: `GitHub returned an error: ${tokenData.error}`,
			});
		}

		return c.json(tokenData);
	},
);

/**
 * ------------------------------------------------------------
 * Gitee OAuth
 * ------------------------------------------------------------
 *
 * 流程：
 *
 * /api/gitee-oauth/authorize
 *        ↓
 * Gitee 登录
 *        ↓
 * /api/gitee-oauth/authorized
 *        ↓
 * /oauth/token
 *        ↓
 * access_token
 */

/**
 * Gitee OAuth 授权入口
 */
app.get(
	"/api/gitee-oauth/authorize",
	async (c) => {
		const env =
			c.env as Record<string, string>;

		const {
			redirect_uri: appReturnUrl,
		} = c.req.query();

		if (!appReturnUrl) {
			c.status(400);

			return c.json({
				error:
					"`redirect_uri` is required.",
			});
		}

		if (!isValidRedirect(appReturnUrl)) {
			c.status(400);

			return c.json({
				error:
					INVALID_REDIRECT_MSG,
			});
		}

		if (
			!isHttpOrHttpsRedirect(
				appReturnUrl,
			)
		) {
			const signSecret =
				c.env.SIGN_SECRETS?.trim();

			if (!signSecret) {
				c.status(500);

				return c.json({
					error:
						"SIGN_SECRETS is not configured.",
				});
			}

			try {
				await verifyRedirectSign(
					c.req.query("sign"),
					signSecret,
				);
			} catch (err: any) {
				c.status(400);

				console.error(
					"[verifyRedirectSign]:",
					err.message,
				);

				return c.json({
					error: err.message,
				});
			}
		}

		const statePayload =
			appReturnUrl;

		const state = await encodeState(
			statePayload,
			env.ENCRYPTION_SECRETS,
		);

		/**
		 * 当前 Worker 的 origin。
		 *
		 * 例如：
		 *
		 * https://oncent-backend.275556817.workers.dev
		 */
		const origin =
			new URL(c.req.url).origin;

		/**
		 * Gitee OAuth Callback。
		 */
		const callback =
			`${origin}/api/gitee-oauth/authorized`;

		const giteeClientId =
			c.env.GITEE_CLIENT_ID?.trim();

		/**
		 * 安全调试日志。
		 *
		 * 不输出 Client Secret。
		 */
		console.log(
			"Gitee OAuth authorize config:",
			{
				clientIdExists:
					!!giteeClientId,

				clientIdLength:
					giteeClientId?.length ?? 0,

				clientIdPreview:
					maskClientId(
						giteeClientId,
					),

				callback,

				origin,
			},
		);

		const authUrl = new URL(
			"https://gitee.com/oauth/authorize",
		);

		authUrl.searchParams.set(
			"client_id",
			giteeClientId,
		);

		authUrl.searchParams.set(
			"redirect_uri",
			callback,
		);

		authUrl.searchParams.set(
			"response_type",
			"code",
		);

		authUrl.searchParams.set(
			"state",
			state,
		);

		console.log(
			"Redirecting user to Gitee for authorization...",
			{
				clientId:
					maskClientId(
						giteeClientId,
					),

				callback,
			},
		);

		return c.redirect(
			authUrl.toString(),
		);
	},
);

/**
 * Gitee OAuth Callback
 *
 * /api/gitee-oauth/authorized
 */
app.get(
	"/api/gitee-oauth/authorized",
	async (c) => {
		const env =
			c.env as Record<string, string>;

		const code =
			c.req.query("code");

		const state =
			c.req.query("state");

		/**
		 * 验证参数
		 */
		if (!code || !state) {
			throw new HTTPException(400, {
				message:
					'Missing "code" or "state" query parameter.',
			});
		}

		let appReturnUrl: string;

		/**
		 * 验证 state
		 */
		try {
			appReturnUrl =
				await decodeState(
					state,
					env.ENCRYPTION_SECRETS,
				);

			console.log(
				"Gitee state validation successful.",
			);
		} catch (err: any) {
			console.error(
				"Invalid state received from Gitee:",
				err,
			);

			throw new HTTPException(400, {
				message:
					err.message,
			});
		}

		if (
			!isValidRedirect(
				appReturnUrl,
			)
		) {
			throw new HTTPException(400, {
				message:
					INVALID_REDIRECT_MSG,
			});
		}

		/**
		 * 当前 Worker origin。
		 */
		const origin =
			new URL(c.req.url).origin;

		/**
		 * 必须和 authorize 阶段使用的 callback
		 * 完全一致。
		 */
		const callback =
			`${origin}/api/gitee-oauth/authorized`;

		/**
		 * 从 Cloudflare 环境变量中读取 Gitee Client。
		 *
		 * trim() 用于排除复制 Client ID / Secret
		 * 时可能带入的前后空格或换行。
		 */
		const giteeClientId =
			c.env.GITEE_CLIENT_ID?.trim();

		const giteeClientSecret =
			c.env.GITEE_CLIENT_SECRET?.trim();

		/**
		 * 安全调试信息。
		 *
		 * 注意：
		 * 绝对不要 console.log(giteeClientSecret)。
		 */
		console.log(
			"Gitee token exchange configuration:",
			{
				clientIdExists:
					!!giteeClientId,

				clientIdLength:
					giteeClientId?.length ?? 0,

				clientIdPreview:
					maskClientId(
						giteeClientId,
					),

				clientSecretExists:
					!!giteeClientSecret,

				clientSecretLength:
					giteeClientSecret?.length ?? 0,

				/**
				 * 如果为 true，说明原始 Cloudflare Secret
				 * 的前后存在空白字符。
				 */
				clientSecretHasWhitespace:
					!!c.env
						.GITEE_CLIENT_SECRET &&
					c.env.GITEE_CLIENT_SECRET !==
						c.env.GITEE_CLIENT_SECRET.trim(),

				callback,

				origin,

				codeExists: !!code,

				codeLength:
					code.length,

				stateExists: !!state,

				stateLength:
					state.length,
			},
		);

		/**
		 * 如果 Client ID / Secret 根本没读取到，
		 * 不要继续请求 Gitee。
		 */
		if (!giteeClientId) {
			console.error(
				"GITEE_CLIENT_ID is missing or empty.",
			);

			throw new HTTPException(500, {
				message:
					"GITEE_CLIENT_ID is not configured in the Worker.",
			});
		}

		if (!giteeClientSecret) {
			console.error(
				"GITEE_CLIENT_SECRET is missing or empty.",
			);

			throw new HTTPException(500, {
				message:
					"GITEE_CLIENT_SECRET is not configured in the Worker.",
			});
		}

		/**
		 * --------------------------------------------------------
		 * 使用 code 交换 access_token
		 * --------------------------------------------------------
		 */
		const params =
			new URLSearchParams({
				grant_type:
					"authorization_code",

				code: code,

				client_id:
					giteeClientId,

				client_secret:
					giteeClientSecret,

				redirect_uri:
					callback,
			});

		console.log(
			"Exchanging code for Gitee access token...",
			{
				clientId:
					maskClientId(
						giteeClientId,
					),

				clientSecretLength:
					giteeClientSecret.length,

				redirectUri:
					callback,

				tokenEndpoint:
					"https://gitee.com/oauth/token",
			},
		);

		const tokenResponse =
			await fetch(
				"https://gitee.com/oauth/token",
				{
					method: "POST",

					headers: {
						"Content-Type":
							"application/x-www-form-urlencoded",

						Accept:
							"application/json",
					},

					body:
						params.toString(),
				},
			);

		/**
		 * 先记录 HTTP 状态。
		 */
		console.log(
			"Gitee token endpoint response:",
			{
				status:
					tokenResponse.status,

				statusText:
					tokenResponse.statusText,

				ok:
					tokenResponse.ok,
			},
		);

		if (!tokenResponse.ok) {
			const errorBody =
				await tokenResponse.text();

			console.error(
				"Failed to get Gitee access token:",
				errorBody,
			);

			throw new HTTPException(500, {
				message:
					"Failed to exchange code for access token (Gitee).",
			});
		}

		const tokenData =
			await tokenResponse.json();

		/**
		 * Gitee 可能在 HTTP 200 时仍然返回 error。
		 */
		if (
			(tokenData as any).error ||
			!(tokenData as any)
				.access_token
		) {
			console.error(
				"Error in Gitee token response:",
				tokenData,
			);

			throw new HTTPException(400, {
				message:
					`Gitee returned an error: ${
						(tokenData as any)
							.error
					}`,
			});
		}

		console.log(
			"Successfully obtained Gitee access token.",
		);

		/**
		 * 将 token 信息带回前端。
		 */
		const returnUrl =
			new URL(appReturnUrl);

		returnUrl.searchParams.set(
			"gitee_authorized",
			JSON.stringify(
				tokenData,
			),
		);

		return c.redirect(
			returnUrl.toString(),
		);
	},
);

/**
 * Gitee Refresh Token
 */
app.post(
	"/api/gitee-oauth/refresh-token",
	async (c) => {
		const body =
			await c.req.json();

		const refreshToken =
			body.refreshToken;

		if (!refreshToken) {
			throw new HTTPException(400, {
				message:
					"invalid refresh token.",
			});
		}

		const giteeClientId =
			c.env.GITEE_CLIENT_ID?.trim();

		const giteeClientSecret =
			c.env.GITEE_CLIENT_SECRET?.trim();

		if (!giteeClientId) {
			throw new HTTPException(500, {
				message:
					"GITEE_CLIENT_ID is not configured in the Worker.",
			});
		}

		if (!giteeClientSecret) {
			throw new HTTPException(500, {
				message:
					"GITEE_CLIENT_SECRET is not configured in the Worker.",
			});
		}

		const params =
			new URLSearchParams({
				grant_type:
					"refresh_token",

				refresh_token:
					refreshToken,

				client_id:
					giteeClientId,

				client_secret:
					giteeClientSecret,
			});

		const tokenResponse =
			await fetch(
				"https://gitee.com/oauth/token",
				{
					method: "POST",

					headers: {
						"Content-Type":
							"application/x-www-form-urlencoded",

						Accept:
							"application/json",
					},

					body:
						params.toString(),
				},
			);

		if (!tokenResponse.ok) {
			const errorBody =
				await tokenResponse.text();

			console.error(
				"Failed to refresh Gitee token:",
				errorBody,
			);

			throw new HTTPException(500, {
				message:
					"Failed to refresh access token (Gitee).",
			});
		}

		const tokenData =
			await tokenResponse.json();

		if (
			(tokenData as any).error ||
			!(tokenData as any)
				.access_token
		) {
			console.error(
				"Error in Gitee refresh response:",
				tokenData,
			);

			throw new HTTPException(400, {
				message:
					`Gitee returned an error: ${
						(tokenData as any)
							.error
					}`,
			});
		}

		return c.json(
			tokenData as any,
		);
	},
);

/**
 * ------------------------------------------------------------
 * 注册子路由
 * ------------------------------------------------------------
 */

// app.route("", proxyRouter);
app.route("", currencyRouter);

export default app;
