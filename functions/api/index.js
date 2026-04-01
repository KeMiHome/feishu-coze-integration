import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// ============================================================================
// Coze OAuth JWT - EdgeOne Pages Functions 适配版
// ============================================================================
// 🔥 核心特性：
// 1. 完全适配 EdgeOne Pages Functions 运行环境
// 2. 使用标准 Web APIs（fetch、Web Crypto）
// 3. 支持 KV 存储进行 Token 缓存（跨请求共享）
// 4. 移除 Node.js 专用依赖，使用原生 fetch 调用 COS
// ============================================================================
// ============================================================================
// 配置常量
// ============================================================================
const CONFIG = {
  // Token 缓存配置
  CACHE: {
    TOKEN_TTL: 86399000,      // Access Token 有效期（24小时）
    JWT_TTL: 3600,             // JWT 有效期（1小时）
    REFRESH_BEFORE: 300000,    // 提前刷新时间（5分钟）
    KV_PREFIX: 'coze_auth_',   // KV 存储前缀
  },
  // 重试配置
  RETRY: {
    MAX_ATTEMPTS: 3,            // 最大重试次数
    BASE_DELAY: 1000,            // 基础延迟（1秒）
    MAX_DELAY: 10000,            // 最大延迟（10秒）
    RETRYABLE_CODES: [401, 429, 500, 502, 503, 504], // 可重试的 HTTP 状态码
  },
  // 超时配置
  TIMEOUT: {
    JWT: 5000,                 // JWT 生成超时
    TOKEN: 10000,               // Token 获取超时
    WORKFLOW: 30000,            // 工作流调用超时
    CONFIG: 10000,              // 配置加载超时
  },
  // API 端点
  ENDPOINTS: {
    TOKEN: 'https://api.coze.cn/api/permission/oauth2/token',
    WORKFLOW: 'https://api.coze.cn/v1/workflow/run',
  },
};

// ============================================================================
// 辅助函数
// ============================================================================
/**
 * 生成随机字符串
 */
function generateRandomString(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * 等待指定时间
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 判断错误是否可重试
 */
function isRetryableError(error) {
  // 网络错误
  if (!error.response && !error.request) {
    return false;
  }
  // 超时错误
  if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
    return true;
  }
  // HTTP 状态码
  if (error.response?.status) {
    return CONFIG.RETRY.RETRYABLE_CODES.includes(error.response.status);
  }
  return false;
}

/**
 * 从腾讯云COS获取文件内容（使用 fetch 实现）
 */
async function getCosObject(fileName, env) {
  const bucket = env.TENCENT_COS_BUCKET;
  const region = env.TENCENT_COS_REGION;
  const secretId = env.TENCENT_COS_SECRET_ID;
  const secretKey = env.TENCENT_COS_SECRET_KEY;

  const key = `config/${fileName}`;
  const host = `${bucket}.cos.${region}.myqcloud.com`;
  const url = `https://${host}/${key}`;

  // 生成 COS 签名（简化版 GET 请求签名）
  const now = Math.floor(Date.now() / 1000);
  const expires = 600; // 10分钟有效期
  const signStr = `get\n\n\n${expires}\n/${key}`;

  // HMAC-SHA1 签名
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secretKey);
  const data = encoder.encode(signStr);

  const keyBuffer = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signatureBuffer = await crypto.subtle.sign('HMAC', keyBuffer, data);
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

  // 构建 URL
  const signedUrl = `${url}?sign=${secretId}/${now}/${expires}/${signature}`;

  try {
    const response = await fetch(signedUrl, {
      method: 'GET',
      headers: {
        'Host': host,
      },
    });

    if (!response.ok) {
      throw new Error(`COS 请求失败: ${response.status} ${response.statusText}`);
    }

    return {
      Body: await response.text(),
    };
  } catch (error) {
    console.error('❌ COS文件获取失败:', error.message);
    throw error;
  }
}

/**
 * 从腾讯云COS加载配置
 */
async function loadConfig(env, useKVCache = true) {
  // 尝试从 KV 加载缓存配置
  if (useKVCache && env.coze_config_kv) {
    try {
      const cachedConfig = await env.coze_config_kv.get('app_config');
      if (cachedConfig) {
        console.log('✅ 使用 KV 缓存的配置');
        return JSON.parse(cachedConfig);
      }
    } catch (error) {
      console.log('⚠️ KV 缓存读取失败，从 COS 加载:', error.message);
    }
  }

  try {
    console.log('🔄 从腾讯云COS加载配置');
    // 并发加载配置文件
    const [secretsResponse, configResponse] = await Promise.all([
      getCosObject('secrets.json', env),
      getCosObject('config.json', env)
    ]);

    // 解析配置
    const secrets = JSON.parse(secretsResponse.Body);
    const config = JSON.parse(configResponse.Body);

    // 合并配置
    const appConfig = {
      ...secrets,
      ...config
    };

    // 尝试缓存到 KV
    if (useKVCache && env.coze_config_kv) {
      try {
        await env.coze_config_kv.put('app_config', JSON.stringify(appConfig), {
          expirationTtl: 300, // 缓存 5 分钟
        });
        console.log('✅ 配置已缓存到 KV');
      } catch (error) {
        console.log('⚠️ KV 缓存写入失败:', error.message);
      }
    }

    console.log('✅ 配置加载成功');
    console.log('📊 配置项数量:', Object.keys(appConfig).length);
    return appConfig;
  } catch (error) {
    console.error('❌ 配置加载失败:', error.message);
    throw error;
  }
}

/**
 * 获取私钥
 */
async function getPrivateKey(env, useKVCache = true) {
  const config = await loadConfig(env, useKVCache);
  let privateKey;

  if (config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
    console.log('🔑 使用 Base64 编码的私钥');
    privateKey = Buffer.from(
      config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
      'base64'
    ).toString('utf-8');
  } else if (config.COZE_JWT_OAUTH_PRIVATE_KEY) {
    console.log('🔑 使用原始私钥');
    privateKey = config.COZE_JWT_OAUTH_PRIVATE_KEY;
    if (privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }
  } else {
    throw new Error('未找到私钥配置');
  }

  console.log('📊 私钥长度:', privateKey.length, '字符');

  // 验证私钥格式
  if (!privateKey.startsWith('-----BEGIN PRIVATE KEY-----') ||
      !privateKey.endsWith('-----END PRIVATE KEY-----')) {
    throw new Error('私钥格式错误，必须包含完整的 PEM 标记');
  }

  console.log('✅ 私钥格式验证通过');
  return privateKey;
}

/**
 * 验证配置
 */
async function validateConfig(env, useKVCache = true) {
  const config = await loadConfig(env, useKVCache);
  const required = [
    'COZE_JWT_OAUTH_CLIENT_ID',
    'COZE_JWT_OAUTH_PUBLIC_KEY_ID',
    'COZE_WORKFLOW_ID',
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
// JWT 生成
// ============================================================================
/**
 * 生成 JWT Token
 */
async function generateJWT(env, useKVCache = true) {
  try {
    console.log('🚀 开始生成 JWT');
    const config = await loadConfig(env, useKVCache);
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
    console.log('   iat:', payload.iat, `(${new Date(payload.iat * 1000).toISOString()})`);
    console.log('   exp:', payload.exp, `(${new Date(payload.exp * 1000).toISOString()})`);
    console.log('   jti:', payload.jti);

    const privateKey = await getPrivateKey(env, useKVCache);
    const pkcs8Key = await importPKCS8(privateKey, 'RS256');
    console.log('✅ 私钥导入成功');

    const jwt = await Promise.race([
      new SignJWT(payload)
        .setProtectedHeader({
          alg: 'RS256',
          kid: config.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
          typ: 'JWT',
        })
        .sign(pkcs8Key),
      sleep(CONFIG.TIMEOUT.JWT).then(() => {
        throw new Error('JWT 生成超时');
      }),
    ]);

    console.log('✅ JWT 生成成功');
    console.log('📊 JWT 长度:', jwt.length, '字符');

    // 验证 JWT 结构
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error(`JWT 格式错误：应该有 3 部分，实际有 ${parts.length} 部分`);
    }

    console.log('✅ JWT 结构验证通过');
    return jwt;
  } catch (error) {
    console.error('❌ JWT 生成失败:', error.message);
    throw error;
  }
}

// ============================================================================
// Access Token 获取
// ============================================================================
/**
 * 获取 Access Token（单次调用）
 */
async function getAccessTokenCozeWay(jwt) {
  console.log('🔄 使用 Coze 特有方式获取 Access Token');
  console.log('💡 JWT 通过 Authorization: Bearer {JWT} 传递');

  const requestBody = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    duration_seconds: CONFIG.CACHE.TOKEN_TTL / 1000,
  };

  console.log('📋 请求体:');
  console.log('   grant_type:', requestBody.grant_type);
  console.log('   duration_seconds:', requestBody.duration_seconds);
  console.log('   JWT 长度:', jwt.length);

  const response = await Promise.race([
    fetch(CONFIG.ENDPOINTS.TOKEN, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${jwt}`,
      },
      body: JSON.stringify(requestBody),
    }),
    sleep(CONFIG.TIMEOUT.TOKEN).then(() => {
      throw new Error('Token 获取超时');
    }),
  ]);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw {
      response: {
        status: response.status,
        data: errorData,
      },
      message: `HTTP ${response.status}: ${response.statusText}`,
    };
  }

  const data = await response.json();
  console.log('✅ Access Token 获取成功！');
  console.log('📊 Token 过期时间:', new Date(data.expires_in * 1000).toISOString());
  return data;
}

/**
 * 获取 Access Token（带重试）
 */
async function getAccessTokenWithRetry(env, useKVCache = true) {
  console.log('🚀 开始获取 Access Token（带重试）');
  await validateConfig(env, useKVCache);
  const jwt = await generateJWT(env, useKVCache);

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const result = await getAccessTokenCozeWay(jwt);
      console.log(`✅ Token 获取成功（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);
      return result;
    } catch (error) {
      console.error(`❌ Token 获取失败（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);

      // 判断是否可重试
      if (attempt >= CONFIG.RETRY.MAX_ATTEMPTS || !isRetryableError(error)) {
        console.error('💡 不再重试，抛出错误');

        // 输出详细错误信息
        if (error.response) {
          console.error('HTTP 状态码:', error.response.status);
          console.error('错误详情:', error.response.data);
          console.error('错误码:', error.response.data?.error_code);
          console.error('错误消息:', error.response.data?.error_message);
        } else {
          console.error('错误类型:', error.code || 'Unknown');
          console.error('错误消息:', error.message);
        }

        throw error;
      }

      // 计算退避时间
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
// 智能缓存策略（基于 KV）
// ============================================================================
/**
 * 获取有效的 Access Token（KV 缓存策略）
 */
async function getValidAccessToken(env, useKVCache = true) {
  const now = Date.now();

  // 尝试从 KV 获取缓存的 Token
  if (useKVCache && env.coze_auth_kv) {
    try {
      const cachedTokenData = await env.coze_auth_kv.get(CONFIG.CACHE.KV_PREFIX + 'access_token', {
        type: 'json',
      });

      if (cachedTokenData) {
        const expiresAt = cachedTokenData.expires_at || 0;
        const timeUntilExpiry = expiresAt - now;

        // Token 有效且距离过期还有足够时间
        if (timeUntilExpiry > CONFIG.CACHE.REFRESH_BEFORE) {
          console.log('✅ 使用 KV 缓存的 Access Token');
          console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
          return cachedTokenData.access_token;
        } else if (timeUntilExpiry > 0) {
          console.warn('⚠️  Token 即将过期，提前刷新');
          console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
        } else {
          console.warn('⚠️  Token 已过期，需要刷新');
        }
      } else {
        console.log('🔄 KV 缓存为空，获取新的 Access Token');
      }
    } catch (error) {
      console.log('⚠️ KV 缓存读取失败:', error.message);
    }
  } else {
    console.log('🔄 KV 未绑定，获取新的 Access Token');
  }

  // 获取新的 Token
  const tokenResponse = await getAccessTokenWithRetry(env, useKVCache);

  // 缓存到 KV
  if (useKVCache && env.coze_auth_kv) {
    try {
      const tokenExpiresAt = tokenResponse.expires_in * 1000;
      const cacheTTL = Math.floor((tokenExpiresAt - now) / 1000);

      await env.coze_auth_kv.put(CONFIG.CACHE.KV_PREFIX + 'access_token', JSON.stringify({
        access_token: tokenResponse.access_token,
        expires_at: tokenExpiresAt,
      }), {
        expirationTtl: Math.max(cacheTTL, 60), // 最小缓存 1 分钟
      });

      console.log('✅ Access Token 已缓存到 KV');
      console.log('📊 缓存过期时间:', new Date(tokenExpiresAt).toISOString());
    } catch (error) {
      console.log('⚠️ KV 缓存写入失败:', error.message);
    }
  }

  return tokenResponse.access_token;
}

// ============================================================================
// 工作流调用（带重试）
// ============================================================================
/**
 * 调用 Coze 工作流（带重试）
 */
async function callCozeWorkflowWithRetry(params, env, useKVCache = true) {
  const config = await loadConfig(env, useKVCache);

  console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证)');
  console.log('📋 工作流 ID:', config.COZE_WORKFLOW_ID);

  const accessToken = await getValidAccessToken(env, useKVCache);
  console.log('✅ Access Token 准备就绪');

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const startTime = Date.now();

      const response = await Promise.race([
        fetch(CONFIG.ENDPOINTS.WORKFLOW, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({
            workflow_id: config.COZE_WORKFLOW_ID,
            parameters: params || {},
            is_async: false,
          }),
        }),
        sleep(CONFIG.TIMEOUT.WORKFLOW).then(() => {
          throw new Error('工作流调用超时');
        }),
      ]);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw {
          response: {
            status: response.status,
            data: errorData,
          },
          message: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const data = await response.json();
      const duration = Date.now() - startTime;

      console.log('✅ 工作流调用成功');
      console.log(`📊 执行耗时: ${duration}ms`);
      return data;
    } catch (error) {
      console.error(`❌ 工作流调用失败（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);

      // 401 错误：清除 KV 缓存
      if (error.response?.status === 401) {
        console.warn('⚠️  Token 可能已过期，清除 KV 缓存');

        if (useKVCache && env.coze_auth_kv) {
          try {
            await env.coze_auth_kv.delete(CONFIG.CACHE.KV_PREFIX + 'access_token');
          } catch (kvError) {
            console.log('⚠️ KV 缓存删除失败:', kvError.message);
          }
        }

        // 重新获取 Token
        if (attempt < CONFIG.RETRY.MAX_ATTEMPTS) {
          console.log('🔄 重新获取 Token 后重试...');
          await getValidAccessToken(env, useKVCache);
          continue;
        }
      }

      // 判断是否可重试
      if (attempt >= CONFIG.RETRY.MAX_ATTEMPTS || !isRetryableError(error)) {
        console.error('💡 不再重试，抛出错误');

        if (error.response) {
          console.error('HTTP 状态码:', error.response.status);
          console.error('错误详情:', error.response.data);
        } else {
          console.error('错误类型:', error.code || 'Unknown');
          console.error('错误消息:', error.message);
        }

        throw error;
      }

      // 计算退避时间
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
// EdgeOne Pages Functions 入口
// ============================================================================
/**
 * API 处理器
 */
export async function onRequest({ request, params, env }) {
  const requestId = generateRandomString(16);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🎯 API 调用开始 [ID: ${requestId}]`);
  console.log('📋 请求方法:', request.method);
  console.log('📋 请求路径:', request.url);
  console.log('📋 请求时间:', new Date().toISOString());

  // 检查请求方法
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({
      success: false,
      error: 'Method not allowed. Use POST.',
      requestId,
    }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const startTime = Date.now();

  try {
    // 解析请求体
    const reqBody = await request.json();

    // 调用 Coze 工作流
    const result = await callCozeWorkflowWithRetry(reqBody.params || {}, env, true);

    const duration = Date.now() - startTime;
    console.log('🎉 API 调用成功');
    console.log(`📊 总耗时: ${duration}ms`);

    return new Response(JSON.stringify({
      success: true,
      data: result,
      authMethod: 'OAuth JWT (EdgeOne Pages Functions)',
      requestId,
      performance: {
        totalDuration: duration,
      },
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (err) {
    const duration = Date.now() - startTime;
    console.error('💥 API 调用失败');
    console.error(`📊 总耗时: ${duration}ms`);

    const errorResponse = {
      success: false,
      error: err.message,
      authMethod: 'OAuth JWT (EdgeOne Pages Functions)',
      requestId,
      performance: {
        totalDuration: duration,
      },
    };

    // 添加详细错误信息
    if (err.response?.data) {
      errorResponse.details = err.response.data;
    }

    return new Response(JSON.stringify(errorResponse), {
      status: err.response?.status || 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } finally {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  }
}
