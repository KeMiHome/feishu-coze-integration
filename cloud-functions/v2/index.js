import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';
import COS from 'cos-nodejs-sdk-v5';

// ============================================================================
// Coze OAuth JWT - 多租户生产版（腾讯云EdgeOne适配）
// ============================================================================
// 核心特性：
// 1. 配置从腾讯云COS加载，解决EdgeOne环境变量长度限制
// 2. 多租户支持：通过User-API-Key识别用户
// 3. 用户信息传递：自动将用户信息传递给Coze工作流
// 4. 智能缓存：Access Token自动缓存与刷新
// 5. 完整错误处理：详细日志与错误分类
// 6. 支持动态 workflow_id（从参数读取，也可使用默认值）
// ============================================================================

// ============================================================================
// 配置常量
// ============================================================================
const CONFIG = {
  CACHE: {
    TOKEN_TTL: 86399000,
    JWT_TTL: 3600,
    REFRESH_BEFORE: 300000,
  },
  RETRY: {
    MAX_ATTEMPTS: 3,
    BASE_DELAY: 1000,
    MAX_DELAY: 10000,
    RETRYABLE_CODES: [401, 429, 500, 502, 503, 504],
  },
  TIMEOUT: {
    JWT: 5000,
    TOKEN: 10000,
    WORKFLOW: 30000,
    CONFIG: 10000,
  },
  ENDPOINTS: {
    TOKEN: 'https://api.coze.cn/api/permission/oauth2/token',
    WORKFLOW: 'https://api.coze.cn/v1/workflow/run',
  },
};

// ============================================================================
// Token 缓存
// ============================================================================
let cachedToken = {
  accessToken: null,
  expiresAt: 0,
  lastRefresh: 0,
  isRefreshing: false,
};

// ============================================================================
// 配置缓存
// ============================================================================
let appConfig = null;
let configExpiry = 0;

// ============================================================================
// 辅助函数
// ============================================================================
function generateRandomString(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isRetryableError(error) {
  if (!error.response && !error.request) return false;
  if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') return true;
  if (error.response?.status) {
    return CONFIG.RETRY.RETRYABLE_CODES.includes(error.response.status);
  }
  return false;
}

// ============================================================================
// 配置加载
// ============================================================================
async function loadConfig(env) {
  if (appConfig && Date.now() < configExpiry) {
    console.log('✅ 使用缓存的配置');
    return appConfig;
  }

  try {
    console.log('🔄 从腾讯云COS加载配置');
    const cosClient = new COS({
      SecretId: env.TENCENT_COS_SECRET_ID,
      SecretKey: env.TENCENT_COS_SECRET_KEY,
    });

    const [secretsResponse, configResponse] = await Promise.all([
      getCosObject(cosClient, env, 'secrets.json'),
      getCosObject(cosClient, env, 'config.json')
    ]);

    const secrets = JSON.parse(secretsResponse.Body.toString());
    const config = JSON.parse(configResponse.Body.toString());

    appConfig = { ...secrets, ...config };
    configExpiry = Date.now() + (5 * 60 * 1000);

    console.log('✅ 配置加载成功');
    console.log('📊 配置项数量:', Object.keys(appConfig).length);
    return appConfig;
  } catch (error) {
    console.error('❌ 配置加载失败:', error.message);
    throw error;
  }
}

async function getCosObject(cosClient, env, fileName) {
  return new Promise((resolve, reject) => {
    cosClient.getObject({
      Bucket: env.TENCENT_COS_BUCKET,
      Region: env.TENCENT_COS_REGION,
      Key: `config/${fileName}`,
      Timeout: CONFIG.TIMEOUT.CONFIG,
    }, (err, data) => {
      if (err) {
        console.error('❌ COS文件获取失败:', err.message);
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}

async function getPrivateKey(config) {
  let privateKey;
  let keySource;

  if (config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
    keySource = 'Base64编码';
    privateKey = Buffer.from(
      config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
      'base64'
    ).toString('utf-8');
  } else if (config.COZE_JWT_OAUTH_PRIVATE_KEY) {
    keySource = '原始字符串';
    privateKey = config.COZE_JWT_OAUTH_PRIVATE_KEY;
    if (privateKey.includes('\\n')) {
      console.log('⚠️  检测到转义字符 \\n，尝试修复...');
      privateKey = privateKey.replace(/\\n/g, '\n');
    }
  } else {
    throw new Error('未找到可用的私钥');
  }

  console.log(`📋 私钥来源: ${keySource}`);
  console.log(`📊 私钥长度: ${privateKey.length} 字符`);

  if (!privateKey.startsWith('-----BEGIN PRIVATE KEY-----') ||
      !privateKey.endsWith('-----END PRIVATE KEY-----')) {
    throw new Error('私钥格式错误');
  }

  console.log('✅ 私钥格式验证通过');
  return privateKey;
}

async function validateConfig(config) {
  const required = [
    'COZE_JWT_OAUTH_CLIENT_ID',
    'COZE_JWT_OAUTH_PUBLIC_KEY_ID',
    'USERS_CONFIG',
    // 注意：COZE_WORKFLOW_ID 不再是必填项，可以从参数传入
  ];
  const errors = [];

  for (const key of required) {
    if (!config[key]) {
      errors.push(`缺少必需的配置项: ${key}`);
    }
  }

  if (!config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 && !config.COZE_JWT_OAUTH_PRIVATE_KEY) {
    errors.push('至少需要配置 COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 或 COZE_JWT_OAUTH_PRIVATE_KEY 其中之一');
  }

  if (errors.length > 0) {
    throw new Error(errors.join('\n'));
  }

  console.log('✅ 配置验证通过');
  return true;
}

// ============================================================================
// 用户管理（多租户功能）
// ============================================================================
async function getUsersConfig(config) {
  try {
    if (config.USERS_CONFIG) {
      const usersConfig = typeof config.USERS_CONFIG === 'string'
        ? JSON.parse(config.USERS_CONFIG)
        : config.USERS_CONFIG;
      console.log('📊 用户配置加载成功');
      console.log('📊 用户数量:', Object.keys(usersConfig.users || {}).length);
      return usersConfig;
    }
    console.warn('⚠️  未找到用户配置');
    return {};
  } catch (error) {
    console.error('❌ 解析用户配置失败:', error.message);
    return {};
  }
}

async function getUserByApiKey(config, apiKey) {
  const usersConfig = await getUsersConfig(config);
  if (!usersConfig.users) {
    console.warn('⚠️  用户配置中没有 users 字段');
    return null;
  }
  const user = usersConfig.users[apiKey];
  if (user) {
    console.log('✅ 找到用户配置:', user.user_name);
    console.log('📊 用户ID:', user.user_id);
    console.log('📊 用户套餐:', user.plan);
  } else {
    console.warn('⚠️  未找到对应的API Key配置');
  }
  return user;
}

async function validateUserCall(request, config) {
  console.log('🔐 开始用户身份验证');
  const apiKey = request.headers.get('user-api-key');
  console.log('📋 请求 Headers 中的 User-API-Key:', apiKey ? apiKey.substring(0, 10) + '...' : '未提供');

  if (!apiKey) {
    console.error('❌ 未提供 User-API-Key');
    throw new Error('未提供User-API-Key');
  }

  const user = await getUserByApiKey(config, apiKey);
  if (!user) {
    console.error('❌ 无效的 User-API-Key');
    throw new Error('无效的User-API-Key');
  }

  if (!user.user_id || !user.user_name || !user.plan) {
    console.error('❌ 用户配置不完整');
    throw new Error('用户配置不完整');
  }

  console.log('✅ 用户认证成功:', user.user_name);
  return {
    user_api_key: apiKey,
    user_id: user.user_id,
    user_name: user.user_name,
    plan: user.plan,
    created_at: user.created_at
  };
}

// ============================================================================
// JWT 生成
// ============================================================================
async function generateJWT(config) {
  try {
    console.log('🚀 开始生成 JWT');

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: config.COZE_JWT_OAUTH_CLIENT_ID,
      aud: 'api.coze.cn',
      iat: now,
      exp: now + CONFIG.CACHE.JWT_TTL,
      jti: generateRandomString(32),
    };

    if (config.COZE_JWT_SESSION_NAME) {
      payload.session_name = config.COZE_JWT_SESSION_NAME;
      console.log('🔐 会话隔离已启用');
    }

    console.log('📋 JWT Payload:');
    console.log('   iss:', payload.iss);
    console.log('   aud:', payload.aud);
    console.log('   iat:', payload.iat);
    console.log('   exp:', payload.exp);
    console.log('   jti:', payload.jti);

    const privateKey = await getPrivateKey(config);
    const pkcs8Key = await importPKCS8(privateKey, 'RS256');

    console.log('✅ 私钥导入成功');

    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: config.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
        typ: 'JWT',
      })
      .sign(pkcs8Key);

    console.log('✅ JWT 生成成功');
    console.log('📊 JWT 长度:', jwt.length, '字符');
    return jwt;
  } catch (error) {
    console.error('❌ JWT 生成失败:', error.message);
    throw error;
  }
}

// ============================================================================
// Access Token 获取
// ============================================================================
async function getAccessTokenCozeWay(jwt) {
  console.log('🔄 使用 Coze 特有方式获取 Access Token');

  const requestBody = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    duration_seconds: CONFIG.CACHE.TOKEN_TTL / 1000,
  };

  const response = await axios.post(
    CONFIG.ENDPOINTS.TOKEN,
    requestBody,
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${jwt}`,
      },
      timeout: CONFIG.TIMEOUT.TOKEN,
    }
  );

  console.log('✅ Access Token 获取成功！');
  return response.data;
}

async function getAccessTokenWithRetry(config) {
  console.log('🚀 开始获取 Access Token（带重试）');
  await validateConfig(config);
  const jwt = await generateJWT(config);

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const result = await getAccessTokenCozeWay(jwt);
      console.log(`✅ Token 获取成功（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);
      return result;
    } catch (error) {
      console.error(`❌ Token 获取失败（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);

      if (attempt >= CONFIG.RETRY.MAX_ATTEMPTS || !isRetryableError(error)) {
        if (error.response) {
          console.error('HTTP 状态码:', error.response.status);
          console.error('错误详情:', error.response.data);
        }
        throw error;
      }

      const delay = Math.min(
        CONFIG.RETRY.BASE_DELAY * Math.pow(2, attempt - 1),
        CONFIG.RETRY.MAX_DELAY
      );
      console.log(`⏳ 等待 ${delay}ms 后重试...`);
      await sleep(delay);
    }
  }
}

// ============================================================================
// 智能缓存策略
// ============================================================================
async function getValidAccessToken(config) {
  const now = Date.now();
  const timeUntilExpiry = cachedToken.expiresAt - now;

  if (cachedToken.accessToken && timeUntilExpiry > CONFIG.CACHE.REFRESH_BEFORE) {
    console.log('✅ 使用缓存的 Access Token');
    console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
    return cachedToken.accessToken;
  }

  if (cachedToken.isRefreshing) {
    console.log('⏳ Token 正在刷新中，等待刷新完成...');
    await sleep(100);
    return getValidAccessToken(config);
  }

  if (cachedToken.accessToken) {
    if (timeUntilExpiry <= 0) {
      console.warn('⚠️  Token 已过期，需要刷新');
    } else {
      console.warn('⚠️  Token 即将过期，提前刷新');
    }
  } else {
    console.log('🔄 缓存为空，获取新的 Access Token');
  }

  cachedToken.isRefreshing = true;

  try {
    const tokenResponse = await getAccessTokenWithRetry(config);
    cachedToken.accessToken = tokenResponse.access_token;
    cachedToken.expiresAt = tokenResponse.expires_in * 1000;
    cachedToken.lastRefresh = now;

    console.log('✅ Access Token 已刷新并缓存');
    return tokenResponse.access_token;
  } finally {
    cachedToken.isRefreshing = false;
  }
}

// ============================================================================
// 工作流调用（多租户版 + 支持动态 workflow_id）
// ============================================================================
async function callCozeWorkflowWithRetry(params, user, config) {
  // 从参数中提取 workflow_id（优先使用参数中的）
  const workflowId = params.workflow_id || config.COZE_WORKFLOW_ID;

  if (!workflowId) {
    throw new Error('未指定 workflow_id，请在参数中传递或配置默认值');
  }

  console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证 - 多租户版)');
  console.log('📋 工作流 ID:', workflowId);
  console.log('📋 来源:', params.workflow_id ? '参数传入' : '配置文件默认值');

  // 显示用户信息
  console.log('👤 用户信息:');
  console.log('   用户ID:', user.user_id);
  console.log('   用户名:', user.user_name);
  console.log('   API Key:', user.user_api_key.substring(0, 10) + '...');
  console.log('   套餐类型:', user.plan);

  const accessToken = await getValidAccessToken(config);
  console.log('✅ Access Token 准备就绪');

  // 从参数中删除 workflow_id，不要传给 Coze API
  const { workflow_id, ...workflowParams } = params;

  // 丰富参数，添加用户信息
  const enrichedParams = {
    ...workflowParams,
    user_context: {
      User_API_Key: user.user_api_key,
      UserName: user.user_name,
      Source: "feishu_workflow",
      Timestamp: new Date().toISOString(),
      UserPlan: user.plan,
      CreatedAt: user.created_at
    }
  };

  console.log('📋 传递给Coze工作流的用户信息:');
  console.log('   UserName:', enrichedParams.user_context.UserName);
  console.log('   Source:', enrichedParams.user_context.Source);

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const startTime = Date.now();
      const response = await axios.post(
        CONFIG.ENDPOINTS.WORKFLOW,
        {
          workflow_id: workflowId,
          parameters: enrichedParams,
          is_async: false,
        },
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          timeout: CONFIG.TIMEOUT.WORKFLOW,
        }
      );

      const duration = Date.now() - startTime;
      console.log('✅ 工作流调用成功');
      console.log(`📊 执行耗时: ${duration}ms`);
      return response.data;
    } catch (error) {
      console.error(`❌ 工作流调用失败（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);

      if (error.response?.status === 401) {
        console.warn('⚠️  Token 可能已过期，清除缓存');
        cachedToken.accessToken = null;
        cachedToken.expiresAt = 0;
        if (attempt < CONFIG.RETRY.MAX_ATTEMPTS) {
          console.log('🔄 重新获取 Token 后重试...');
          await getValidAccessToken(config);
          continue;
        }
      }

      if (attempt >= CONFIG.RETRY.MAX_ATTEMPTS || !isRetryableError(error)) {
        if (error.response) {
          console.error('HTTP 状态码:', error.response.status);
          console.error('错误详情:', error.response.data);
        }
        throw error;
      }

      const delay = Math.min(
        CONFIG.RETRY.BASE_DELAY * Math.pow(2, attempt - 1),
        CONFIG.RETRY.MAX_DELAY
      );
      console.log(`⏳ 等待 ${delay}ms 后重试...`);
      await sleep(delay);
    }
  }
}

// ============================================================================
// EdgeOne Pages Function Handler
// ============================================================================
export async function onRequest(context) {
  const { request, env } = context;
  const requestId = generateRandomString(16);

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🎯 API 调用开始 [ID: ${requestId}]`);
  console.log('📋 请求方法:', request.method);
  console.log('📋 请求路径:', request.url);
  console.log('📋 请求时间:', new Date().toISOString());

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({
      success: false,
      error: 'Method not allowed',
      requestId,
    }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const startTime = Date.now();

  try {
    // 加载配置
    const config = await loadConfig(env);

    // 多租户用户验证
    const user = await validateUserCall(request, config);

    // 解析请求体
    const reqBody = await request.json();

    // 调用工作流（带用户信息）
    const result = await callCozeWorkflowWithRetry(reqBody.params || {}, user, config);

    const duration = Date.now() - startTime;
    console.log('🎉 API 调用成功');
    console.log(`📊 总耗时: ${duration}ms`);

    return new Response(JSON.stringify({
      success: true,
      data: result,
      user: {
        user_id: user.user_id,
        user_name: user.user_name,
        plan: user.plan
      },
      authMethod: 'OAuth JWT (Multi-Tenant)',
      requestId,
      performance: {
        totalDuration: duration,
        tokenRemainingSeconds: Math.max(0, Math.floor((cachedToken.expiresAt - Date.now()) / 1000)),
        tokenExpiresAt: new Date(cachedToken.expiresAt).toISOString(),
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    const duration = Date.now() - startTime;
    console.error('💥 API 调用失败:', err.message);
    console.error(`📊 总耗时: ${duration}ms`);

    const errorResponse = {
      success: false,
      error: err.message,
      authMethod: 'OAuth JWT (Multi-Tenant)',
      requestId,
      performance: {
        totalDuration: duration,
        tokenRemainingSeconds: cachedToken.accessToken ?
          Math.max(0, Math.floor((cachedToken.expiresAt - Date.now()) / 1000)) : 0,
      },
    };

    if (err.response?.data) {
      errorResponse.details = err.response.data;
    }

    return new Response(JSON.stringify(errorResponse), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  } finally {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  }
}
