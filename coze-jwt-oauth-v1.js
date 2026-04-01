import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';
import COS from 'cos-nodejs-sdk-v5';

// ============================================================================
// Coze OAuth JWT - 生产级完整版（腾讯云EdgeOne适配）
// ============================================================================
// 🔥 核心特性：
// 1. 配置从腾讯云COS加载，解决EdgeOne环境变量长度限制
// 2. 智能缓存策略：提前刷新Token，避免请求失败
// 3. 指数退避重试：对可重试错误自动重试
// 4. 完善的错误处理：详细的日志和错误分类
// ============================================================================

// ============================================================================
// 配置常量
// ============================================================================

const CONFIG = {
  // Token 缓存配置
  CACHE: {
    TOKEN_TTL: 86399000,      // Access Token 有效期（24小时）
    JWT_TTL: 3600,             // JWT 有效期（1小时）
    REFRESH_BEFORE: 300000,      // 提前刷新时间（5分钟）
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
// 腾讯云COS客户端
// ============================================================================

const cosClient = new COS({
  SecretId: process.env.TENCENT_COS_SECRET_ID,
  SecretKey: process.env.TENCENT_COS_SECRET_KEY,
});

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * 生成随机字符串
 * @param {number} length - 字符串长度
 * @returns {string}
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
 * @param {number} ms - 等待时间（毫秒）
 * @returns {Promise}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 判断错误是否可重试
 * @param {Error} error - 错误对象
 * @returns {boolean}
 */
function isRetryableError(error) {
  // 网络错误
  if (!error.response && !error.request) {
    return false; // 配置错误等不可重试
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
 * 从腾讯云COS加载配置
 */
async function loadConfig() {
  // 检查配置缓存是否有效（缓存5分钟）
  if (appConfig && Date.now() < configExpiry) {
    console.log('✅ 使用缓存的配置');
    return appConfig;
  }

  try {
    console.log('🔄 从腾讯云COS加载配置');

    // 并发加载配置文件
    const [secretsResponse, configResponse] = await Promise.all([
      getCosObject('secrets.json'),
      getCosObject('config.json')
    ]);

    // 解析配置
    const secrets = JSON.parse(secretsResponse.Body.toString());
    const config = JSON.parse(configResponse.Body.toString());

    // 合并配置
    appConfig = {
      ...secrets,
      ...config
    };

    // 设置配置缓存过期时间（5分钟）
    configExpiry = Date.now() + (5 * 60 * 1000);

    console.log('✅ 配置加载成功');
    console.log('📊 配置项数量:', Object.keys(appConfig).length);

    return appConfig;
  } catch (error) {
    console.error('❌ 配置加载失败:', error.message);
    throw error;
  }
}

/**
 * 从腾讯云COS获取文件内容
 */
async function getCosObject(fileName) {
  return new Promise((resolve, reject) => {
    cosClient.getObject({
      Bucket: process.env.TENCENT_COS_BUCKET,
      Region: process.env.TENCENT_COS_REGION,
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

/**
 * 获取私钥
 * @returns {string}
 * @throws {Error}
 */
async function getPrivateKey() {
  const config = await loadConfig();
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
 * @throws {Error}
 */
async function validateConfig() {
  const config = await loadConfig();

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
 * @returns {Promise<string>}
 * @throws {Error}
 */
async function generateJWT() {
  try {
    console.log('🚀 开始生成 JWT');

    const config = await loadConfig();
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

    const privateKey = await getPrivateKey();
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
// Access Token 获取（Coze 特有方式）
// ============================================================================

/**
 * 获取 Access Token（单次调用，不包含重试）
 * @param {string} jwt - JWT Token
 * @returns {Promise<Object>}
 * @throws {Error}
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
    axios.post(
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
    ),
    sleep(CONFIG.TIMEOUT.TOKEN).then(() => {
      throw new Error('Token 获取超时');
    }),
  ]);

  console.log('✅ Access Token 获取成功！');
  console.log('📊 Token 过期时间:', new Date(response.data.expires_in * 1000).toISOString());

  return response.data;
}

/**
 * 获取 Access Token（带重试）
 * @returns {Promise<Object>}
 * @throws {Error}
 */
async function getAccessTokenWithRetry() {
  console.log('🚀 开始获取 Access Token（带重试）');

  await validateConfig();

  const jwt = await generateJWT();

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
// 智能缓存策略
// ============================================================================

/**
 * 获取有效的 Access Token（智能缓存策略）
 * @returns {Promise<string>}
 * @throws {Error}
 */
async function getValidAccessToken() {
  const now = Date.now();
  const timeUntilExpiry = cachedToken.expiresAt - now;

  // Token 有效且距离过期还有足够时间
  if (cachedToken.accessToken && timeUntilExpiry > CONFIG.CACHE.REFRESH_BEFORE) {
    console.log('✅ 使用缓存的 Access Token');
    console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
    return cachedToken.accessToken;
  }

  // 检查是否正在刷新（防止并发刷新）
  if (cachedToken.isRefreshing) {
    console.log('⏳ Token 正在刷新中，等待刷新完成...');
    await sleep(100);
    return getValidAccessToken();
  }

  // Token 即将过期或已过期，需要刷新
  if (cachedToken.accessToken) {
    if (timeUntilExpiry <= 0) {
      console.warn('⚠️  Token 已过期，需要刷新');
    } else {
      console.warn('⚠️  Token 即将过期，提前刷新');
      console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
    }
  } else {
    console.log('🔄 缓存为空，获取新的 Access Token');
  }

  // 标记正在刷新
  cachedToken.isRefreshing = true;

  try {
    const tokenResponse = await getAccessTokenWithRetry();

    // 更新缓存
    cachedToken.accessToken = tokenResponse.access_token;
    cachedToken.expiresAt = tokenResponse.expires_in * 1000;
    cachedToken.lastRefresh = now;

    console.log('✅ Access Token 已刷新并缓存');
    console.log('📊 过期时间:', new Date(cachedToken.expiresAt).toISOString());
    console.log('📊 有效期:', Math.floor((cachedToken.expiresAt - now) / 1000), '秒');

    return tokenResponse.access_token;
  } finally {
    cachedToken.isRefreshing = false;
  }
}

// ============================================================================
// 工作流调用（带重试）
// ============================================================================

/**
 * 调用 Coze 工作流（带重试）
 * @param {Object} params - 工作流参数
 * @returns {Promise<Object>}
 * @throws {Error}
 */
async function callCozeWorkflowWithRetry(params) {
  const config = await loadConfig();
  
  console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证)');
  console.log('📋 工作流 ID:', config.COZE_WORKFLOW_ID);

  const accessToken = await getValidAccessToken();
  console.log('✅ Access Token 准备就绪');

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const startTime = Date.now();

      const response = await Promise.race([
        axios.post(
          CONFIG.ENDPOINTS.WORKFLOW,
          {
            workflow_id: config.COZE_WORKFLOW_ID,
            parameters: params || {},
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
        ),
        sleep(CONFIG.TIMEOUT.WORKFLOW).then(() => {
          throw new Error('工作流调用超时');
        }),
      ]);

      const duration = Date.now() - startTime;
      console.log('✅ 工作流调用成功');
      console.log(`📊 执行耗时: ${duration}ms`);

      return response.data;

    } catch (error) {
      console.error(`❌ 工作流调用失败（尝试 ${attempt}/${CONFIG.RETRY.MAX_ATTEMPTS}）`);

      // 401 错误：清除 Token 缓存
      if (error.response?.status === 401) {
        console.warn('⚠️  Token 可能已过期，清除缓存');
        cachedToken.accessToken = null;
        cachedToken.expiresAt = 0;

        // 重新获取 Token
        if (attempt < CONFIG.RETRY.MAX_ATTEMPTS) {
          console.log('🔄 重新获取 Token 后重试...');
          await getValidAccessToken();
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
// EdgeOne API 入口
// ============================================================================

/**
 * API 处理器
 * @param {Object} request - 请求对象
 * @param {Object} context - 上下文对象
 */
export default async function handler(request, context) {
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
    // 解析请求体
    const reqBody = await request.json();
    const result = await callCozeWorkflowWithRetry(reqBody.params || {});

    const duration = Date.now() - startTime;
    console.log('🎉 API 调用成功');
    console.log(`📊 总耗时: ${duration}ms`);

    return new Response(JSON.stringify({
      success: true,
      data: result,
      authMethod: 'OAuth JWT (Production-Ready)',
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
    console.error('💥 API 调用失败');
    console.error(`📊 总耗时: ${duration}ms`);

    const errorResponse = {
      success: false,
      error: err.message,
      authMethod: 'OAuth JWT (Production-Ready)',
      requestId,
      performance: {
        totalDuration: duration,
        tokenRemainingSeconds: cachedToken.accessToken ?
          Math.max(0, Math.floor((cachedToken.expiresAt - Date.now()) / 1000)) : 0,
      },
    };

    // 添加详细错误信息（仅开发环境）
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

// ============================================================================
// 本地测试代码
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🧪 本地测试模式\n');

  // 设置测试环境变量
  process.env.TENCENT_COS_SECRET_ID = 'your-cos-secret-id';
  process.env.TENCENT_COS_SECRET_KEY = 'your-cos-secret-key';
  process.env.TENCENT_COS_BUCKET = 'your-bucket-name';
  process.env.TENCENT_COS_REGION = 'ap-guangzhou';

  // 测试配置加载
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📝 测试配置加载');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    await loadConfig();
    console.log('\n✅ 配置加载测试通过\n');
  } catch (error) {
    console.error('\n❌ 配置加载测试失败:', error.message, '\n');
  }

  // 测试 JWT 生成
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📝 测试 JWT 生成');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    await generateJWT();
    console.log('\n✅ JWT 生成测试通过\n');
  } catch (error) {
    console.error('\n❌ JWT 生成测试失败:', error.message, '\n');
  }
}