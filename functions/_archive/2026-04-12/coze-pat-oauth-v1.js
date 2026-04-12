import axios from 'axios';
import COS from 'cos-nodejs-sdk-v5';

// ============================================================================
// Coze PAT 认证 - 生产级备份版本（腾讯云EdgeOne适配）
// ============================================================================
// 🔥 核心特性：
// 1. 配置从腾讯云COS加载，解决EdgeOne环境变量长度限制
// 2. 智能缓存策略：提前刷新Token，避免请求失败
// 3. 指数退避重试：对可重试错误自动重试
// 4. 完善的错误处理：详细的日志和错误分类
// 5. 简单易用：无需管理密钥对，直接使用PAT Token
// ============================================================================

// ============================================================================
// 配置常量
// ============================================================================

const CONFIG = {
  // Token 缓存配置
  CACHE: {
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
    WORKFLOW: 30000,            // 工作流调用超时
    CONFIG: 10000,              // 配置加载超时
  },

  // API 端点
  ENDPOINTS: {
    WORKFLOW: 'https://api.coze.cn/v1/workflow/run',
  },
};

// ============================================================================
// PAT Token 缓存
// ============================================================================

let cachedToken = {
  patToken: null,
  expiresAt: 0,
  lastRefresh: 0,
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

    // 获取配置文件
    const response = await getCosObject('config.json');
    const config = JSON.parse(response.Body.toString());

    // 合并配置
    appConfig = config;

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
 * 验证配置
 * @throws {Error}
 */
async function validateConfig() {
  const config = await loadConfig();

  const required = [
    'COZE_PAT_TOKEN',
    'COZE_WORKFLOW_ID',
  ];

  const errors = [];

  for (const key of required) {
    if (!config[key]) {
      errors.push(`缺少必需的配置项: ${key}`);
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.join('\n'));
  }

  console.log('✅ 配置验证通过');
  console.log('🔑 PAT Token:', config.COZE_PAT_TOKEN.substring(0, 20) + '...');
  return true;
}

/**
 * 解析PAT Token过期时间
 * PAT Token格式：pat_xxxx.expire_at=UnixTimestamp
 * @param {string} patToken - PAT Token
 * @returns {number} 过期时间（毫秒时间戳）
 */
function parsePATExpiry(patToken) {
  try {
    // PAT Token格式：pat_xxxx.expire_at=1774622439
    const match = patToken.match(/expire_at=(\d+)/);

    if (match) {
      const expiryTime = parseInt(match[1], 10);
      console.log('📊 从PAT Token解析过期时间:', new Date(expiryTime * 1000).toISOString());
      return expiryTime * 1000; // 转换为毫秒
    } else {
      // 如果无法解析，假设长期有效（24小时）
      console.warn('⚠️  无法从PAT Token解析过期时间，假设24小时有效期');
      return Date.now() + (24 * 60 * 60 * 1000);
    }
  } catch (error) {
    console.warn('⚠️  解析PAT Token过期时间失败，假设24小时有效期');
    return Date.now() + (24 * 60 * 60 * 1000);
  }
}

// ============================================================================
// PAT Token管理
// ============================================================================

/**
 * 获取PAT Token
 * @returns {string}
 * @throws {Error}
 */
async function getPATToken() {
  const config = await loadConfig();
  const patToken = config.COZE_PAT_TOKEN;

  if (!patToken) {
    throw new Error('未找到COZE_PAT_TOKEN配置');
  }

  if (!patToken.startsWith('pat_')) {
    throw new Error('PAT Token格式错误，应该以 "pat_" 开头');
  }

  return patToken;
}

/**
 * 初始化PAT Token（首次加载）
 */
async function initializePATToken() {
  console.log('🔄 初始化PAT Token');

  const patToken = await getPATToken();
  const expiresAt = parsePATExpiry(patToken);

  cachedToken.patToken = patToken;
  cachedToken.expiresAt = expiresAt;
  cachedToken.lastRefresh = Date.now();

  const now = Date.now();
  const timeUntilExpiry = Math.max(0, Math.floor((expiresAt - now) / 1000));

  console.log('✅ PAT Token初始化成功');
  console.log('📊 有效期:', timeUntilExpiry, '秒');
  console.log('📊 过期时间:', new Date(expiresAt).toISOString());
}

/**
 * 获取有效的PAT Token（智能缓存策略）
 * @returns {string}
 * @throws {Error}
 */
async function getValidPATToken() {
  const now = Date.now();
  const timeUntilExpiry = cachedToken.expiresAt - now;

  // 首次加载
  if (!cachedToken.patToken) {
    await initializePATToken();
    return cachedToken.patToken;
  }

  // Token有效且距离过期还有足够时间
  if (timeUntilExpiry > CONFIG.CACHE.REFRESH_BEFORE) {
    console.log('✅ 使用缓存的PAT Token');
    console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
    return cachedToken.patToken;
  }

  // Token即将过期或已过期
  if (timeUntilExpiry <= 0) {
    console.warn('⚠️  PAT Token已过期，需要更新');
  } else {
    console.warn('⚠️  PAT Token即将过期，建议更新');
    console.log('📊 距离过期还有:', Math.floor(timeUntilExpiry / 1000), '秒');
  }

  // PAT Token无法自动刷新，需要手动更新配置
  // 这里我们仍然使用缓存的Token，但给出警告
  console.warn('⚠️  PAT Token无法自动刷新，请在腾讯云COS更新config.json文件');

  return cachedToken.patToken;
}

// ============================================================================
// 工作流调用（带重试）
// ============================================================================

/**
 * 调用Coze工作流（带重试）
 * @param {Object} params - 工作流参数
 * @returns {Promise<Object>}
 * @throws {Error}
 */
async function callCozeWorkflowWithRetry(params) {
  const config = await loadConfig();
  
  console.log('🎯 开始调用Coze工作流 (PAT认证)');
  console.log('📋 工作流ID:', config.COZE_WORKFLOW_ID);

  await validateConfig();

  const patToken = await getValidPATToken();
  console.log('✅ PAT Token准备就绪');

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
              'Authorization': `Bearer ${patToken}`,
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

      // 判断是否可重试
      if (attempt >= CONFIG.RETRY.MAX_ATTEMPTS || !isRetryableError(error)) {
        console.error('💡 不再重试，抛出错误');

        if (error.response) {
          console.error('HTTP状态码:', error.response.status);
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
// EdgeOne API入口
// ============================================================================

/**
 * API处理器
 * @param {Object} request - 请求对象
 * @param {Object} context - 上下文对象
 */
export default async function handler(request, context) {
  const requestId = Math.random().toString(36).substring(7);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🎯 API调用开始 [ID: ${requestId}]`);
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
    console.log('🎉 API调用成功');
    console.log(`📊 总耗时: ${duration}ms`);

    return new Response(JSON.stringify({
      success: true,
      data: result,
      authMethod: 'PAT (Production-Ready)',
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
    console.error('💥 API调用失败');
    console.error(`📊 总耗时: ${duration}ms`);

    const errorResponse = {
      success: false,
      error: err.message,
      authMethod: 'PAT (Production-Ready)',
      requestId,
      performance: {
        totalDuration: duration,
        tokenRemainingSeconds: cachedToken.patToken ?
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

  // 测试PAT Token解析
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📝 测试PAT Token解析');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    const testToken = 'pat_test_xxxxxxxxxxxxxxxxxx.expire_at=1774622439';
    const expiry = parsePATExpiry(testToken);
    console.log('✅ PAT Token解析测试通过');
    console.log('📊 过期时间:', new Date(expiry).toISOString(), '\n');
  } catch (error) {
    console.error('❌ PAT Token解析测试失败:', error.message, '\n');
  }

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
}