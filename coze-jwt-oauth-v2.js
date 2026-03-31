import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';
import COS from 'cos-nodejs-sdk-v5';

// ============================================================================
// Coze OAuth JWT - 多租户生产版（基于final-v2的调试信息）- 腾讯云EdgeOne适配
// ============================================================================
// 核心特性：
// 1. 配置从腾讯云COS加载，解决EdgeOne环境变量长度限制
// 2. 多租户支持：通过User-API-Key识别用户
// 3. 用户信息传递：自动将用户信息传递给Coze工作流
// 4. 智能缓存：Access Token自动缓存与刷新
// 5. 完整错误处理：详细日志与错误分类
// 6. 保留final-v2的所有调试信息
// ============================================================================
//
// 腾讯云环境变量配置：
//
// COS访问配置：
//   TENCENT_COS_SECRET_ID=你的COS Secret ID
//   TENCENT_COS_SECRET_KEY=你的COS Secret Key
//   TENCENT_COS_BUCKET=你的COS存储桶名称
//   TENCENT_COS_REGION=你的COS地域（如：ap-guangzhou）
//
// 腾讯云COS文件配置：
// config/secrets.json:
//   {
//     "COZE_JWT_OAUTH_CLIENT_ID": "你的客户端ID",
//     "COZE_JWT_OAUTH_PUBLIC_KEY_ID": "你的公钥ID",
//     "COZE_JWT_OAUTH_PRIVATE_KEY_BASE64": "你的私钥Base64编码"
//   }
//
// config/config.json:
//   {
//     "COZE_WORKFLOW_ID": "你的工作流ID",
//     "COZE_JWT_SESSION_NAME": "会话名称（可选）",
//     "USERS_CONFIG": {
//       "users": {
//         "user_secret_token_abc123": {
//           "user_id": "user_001",
//           "user_name": "Vincent圈2012",
//           "plan": "free",
//           "created_at": "2026-03-31T11:46:00Z"
//         }
//       }
//     }
//   }
//
// 注意：
// - USERS_CONFIG必须是压缩后的单行JSON字符串
// - 不要包含换行符或多余空格
// ============================================================================

/**
 * JWT Token 缓存
 */
let cachedToken = {
  accessToken: null,
  expiresAt: 0,
};

/**
 * 配置缓存
 */
let appConfig = null;
let configExpiry = 0;

/**
 * 腾讯云COS客户端
 */
const cosClient = new COS({
  SecretId: process.env.TENCENT_COS_SECRET_ID,
  SecretKey: process.env.TENCENT_COS_SECRET_KEY,
});

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
      Timeout: 10000,
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
 */
async function validateConfig() {
  const config = await loadConfig();

  const required = [
    'COZE_JWT_OAUTH_CLIENT_ID',
    'COZE_JWT_OAUTH_PUBLIC_KEY_ID',
    'COZE_WORKFLOW_ID',
    'USERS_CONFIG', // 新增：多租户必需
  ];

  const optional = [
    'COZE_JWT_OAUTH_PRIVATE_KEY_BASE64',
    'COZE_JWT_OAUTH_PRIVATE_KEY',
    'COZE_JWT_SESSION_NAME',
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

/**
 * 用户管理 - 新增多租户功能
 */

/**
 * 获取用户配置
 */
async function getUsersConfig() {
  try {
    const config = await loadConfig();
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
    console.error('💡 请检查 config.json 中的 USERS_CONFIG 是否为有效的 JSON 格式');
    return {};
  }
}

/**
 * 根据API Key获取用户信息
 */
async function getUserByApiKey(apiKey) {
  const usersConfig = await getUsersConfig();

  if (!usersConfig.users) {
    console.warn('⚠️  用户配置中没有 users 字段');
    return null;
  }

  const user = usersConfig.users[apiKey];

  if (user) {
    console.log('✅ 找到用户配置:', user.user_name);
    console.log('📊 用户ID:', user.user_id);
    console.log('📊 用户套餐:', user.plan);
    console.log('📊 创建时间:', user.created_at);
  } else {
    console.warn('⚠️  未找到对应的API Key配置');
    console.log('💡 请检查该API Key是否已在 config.json 的 USERS_CONFIG 中配置');
  }

  return user;
}

/**
 * 验证用户调用 - 新增多租户认证
 */
async function validateUserCall(request) {
  console.log('🔐 开始用户身份验证');

  const headers = Object.fromEntries(request.headers.entries());
  const apiKey = headers['user-api-key'];

  console.log('📋 请求 Headers 中的 User-API-Key:', apiKey ? apiKey.substring(0, 10) + '...' : '未提供');

  if (!apiKey) {
    console.error('❌ 未提供 User-API-Key');
    console.error('💡 请在请求头中添加：User-API-Key: <your-api-key>');
    throw new Error('未提供User-API-Key');
  }

  const user = await getUserByApiKey(apiKey);

  if (!user) {
    console.error('❌ 无效的 User-API-Key');
    console.error('💡 请检查该API Key是否已在 config.json 的 USERS_CONFIG 环境变量中配置');
    throw new Error('无效的User-API-Key');
  }

  // 验证必填字段
  if (!user.user_id) {
    console.error('❌ 用户配置缺少 user_id 字段');
    throw new Error('用户配置不完整：缺少user_id');
  }

  if (!user.user_name) {
    console.error('❌ 用户配置缺少 user_name 字段');
    throw new Error('用户配置不完整：缺少user_name');
  }

  if (!user.plan) {
    console.error('❌ 用户配置缺少 plan 字段');
    throw new Error('用户配置不完整：缺少plan');
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

/**
 * 生成随机字符串（用于 JWT 的 jti）
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
 * 获取私钥
 */
async function getPrivateKey() {
  const config = await loadConfig();
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
      console.log('✅ 已修复转义字符');
    }
  } else {
    throw new Error('未找到可用的私钥');
  }

  console.log(`📋 私钥来源: ${keySource}`);
  console.log(`📊 私钥长度: ${privateKey.length} 字符`);

  // 检查私钥格式
  const startsCorrectly = privateKey.startsWith('-----BEGIN PRIVATE KEY-----');
  const endsCorrectly = privateKey.endsWith('-----END PRIVATE KEY-----');

  if (!startsCorrectly || !endsCorrectly) {
    console.error('❌ 私钥格式错误');
    console.error('💡 私钥必须包含完整的 BEGIN/END 标记');
    console.error('💡 开头:', privateKey.substring(0, 50));
    console.error('💡 结尾:', privateKey.substring(privateKey.length - 50));
    throw new Error('私钥格式错误');
  }

  console.log('✅ 私钥格式验证通过');
  return privateKey;
}

/**
 * 生成 JWT Token
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
      exp: now + 3600,
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
    console.log('   iat类型:', typeof payload.iat);
    console.log('   exp类型:', typeof payload.exp);
    console.log('   jti:', payload.jti);

    const privateKey = await getPrivateKey();
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

    // 验证 JWT 结构
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error(`JWT 格式错误：应该有 3 部分，实际有 ${parts.length} 部分`);
    }
    console.log('✅ JWT 结构验证通过');

    // 验证每一部分的长度
    console.log('📊 JWT 各部分长度:');
    console.log('   Header:', parts[0].length, '字符');
    console.log('   Payload:', parts[1].length, '字符');
    console.log('   Signature:', parts[2].length, '字符');

    // 检查是否有特殊字符
    const specialChars = [];
    for (let i = 0; i < jwt.length; i++) {
      const charCode = jwt.charCodeAt(i);
      if (charCode > 127) {
        specialChars.push({
          index: i,
          char: jwt[i],
          code: charCode,
        });
      }
    }

    if (specialChars.length > 0) {
      console.warn('⚠️  发现非 ASCII 字符:', specialChars.length, '个');
      specialChars.forEach(item => {
        console.warn(`   位置 ${item.index}: "${item.char}" (编码: ${item.code})`);
      });
    } else {
      console.log('✅ 未发现非 ASCII 字符');
    }

    return jwt;

  } catch (error) {
    console.error('❌ JWT 生成失败:', error.message);
    throw error;
  }
}

/**
 * 使用 URL 编码格式获取 Access Token
 */
async function getAccessTokenURLEncoded(jwt) {
  console.log('🔄 尝试方式 1: URL 编码格式（OAuth 2.0 标准）');

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', jwt);
  params.append('duration_seconds', '86399'); // ✅ 修复：duration_seconds (24小时)

  console.log('📋 请求体（URL 编码）:');
  console.log('   grant_type:', params.get('grant_type'));
  console.log('   assertion长度:', params.get('assertion')?.length);
  console.log('   assertion前50字符:', params.get('assertion')?.substring(0, 50));
  console.log('   duration_seconds:', params.get('duration_seconds'));
  console.log('');
  console.log('📋 完整请求体字符串:');
  console.log(params.toString());

  const response = await axios.post(
    'https://api.coze.cn/api/permission/oauth2/token',
    params,
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      timeout: 10000,
    }
  );

  console.log('✅ 方式 1 成功！');
  return response.data;
}

/**
 * 使用 JSON 格式获取 Access Token
 */
async function getAccessTokenJSON(jwt) {
  console.log('🔄 尝试方式 2: JSON 格式');

  const requestBody = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
    duration_seconds: 86399, // ✅ 修复：duration_seconds (24小时)
  };

  console.log('📋 请求体（JSON）:');
  console.log('   grant_type:', requestBody.grant_type);
  console.log('   assertion长度:', requestBody.assertion?.length);
  console.log('   assertion前50字符:', requestBody.assertion?.substring(0, 50));
  console.log('   duration_seconds:', requestBody.duration_seconds);
  console.log('');
  console.log('📋 完整请求体（JSON）:');
  console.log(JSON.stringify(requestBody, null, 2));

  const response = await axios.post(
    'https://api.coze.cn/api/permission/oauth2/token',
    requestBody,
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      timeout: 10000,
    }
  );

  console.log('✅ 方式 2 成功！');
  return response.data;
}

/**
 * 获取 Access Token（自动尝试多种格式）
 */
async function getAccessToken() {
  try {
    console.log('🚀 开始获取 Access Token');

    // 验证配置
    await validateConfig();

    // 生成 JWT
    const jwt = await generateJWT();

    // 先尝试 URL 编码格式（OAuth 2.0 标准）
    try {
      return await getAccessTokenURLEncoded(jwt);
    } catch (error1) {
      console.log('❌ 方式 1 失败');
      console.error('HTTP 状态码:', error1.response?.status);
      console.error('错误详情:', error1.response?.data);
      console.error('错误消息:', error1.message);
      console.log('');

      // 如果 URL 编码失败，尝试 JSON 格式
      try {
        return await getAccessTokenJSON(jwt);
      } catch (error2) {
        console.log('❌ 方式 2 失败');
        console.error('HTTP 状态码:', error2.response?.status);
        console.error('错误详情:', error2.response?.data);
        console.error('错误消息:', error2.message);
        console.log('');

        // 两种方式都失败，抛出错误
        throw new Error('所有 Token 获取方式都失败');
      }
    }

  } catch (error) {
    console.error('❌ 获取 Access Token 失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);
      console.error('错误码:', error.response.data?.error_code || error.response.data?.code);
      console.error('错误消息:', error.response.data?.error_message || error.response.data?.msg);

      if (error.response.data?.error_message?.includes('empty jwt')) {
        console.error('');
        console.error('💡 特殊错误：JWT 被识别为空');
        console.error('💡 可能原因：');
        console.error('   1. JWT 包含特殊字符导致解析失败');
        console.error('   2. JWT 格式不符合 Coze 期望');
        console.error('   3. assertion 字段未正确传递');
        console.error('   4. URLSearchParams 编码问题');
        console.error('');
        console.error('💡 排查步骤：');
        console.error('   1. 检查腾讯云EdgeOne日志中的完整请求体');
        console.error('   2. 对比官方文档的请求格式');
        console.error('   3. 尝试手动构造请求测试');
      }
    } else if (error.request) {
      console.error('💡 网络错误：无法连接到 Coze API');
    } else {
      console.error('💡 其他错误:', error.message);
    }

    throw error;
  }
}

/**
 * 获取有效的 Access Token（带缓存和自动刷新）
 */
async function getValidAccessToken() {
  const now = Date.now();

  if (cachedToken.accessToken && cachedToken.expiresAt > now + 30000) {
    console.log('✅ 使用缓存的 Access Token');
    console.log('📊 距离过期还有:', Math.floor((cachedToken.expiresAt - now) / 1000), '秒');
    return cachedToken.accessToken;
  }

  console.log('🔄 缓存失效，获取新的 Access Token');

  const tokenResponse = await getAccessToken();

  cachedToken.accessToken = tokenResponse.access_token;
  cachedToken.expiresAt = now + (tokenResponse.expires_in || 3600) * 1000;

  console.log('✅ Access Token 已缓存');
  console.log('📊 过期时间:', new Date(cachedToken.expiresAt).toISOString());

  return tokenResponse.access_token;
}

/**
 * 调用 Coze 工作流（多租户版）- 新增用户信息传递
 */
async function callCozeWorkflow(params, user) {
  try {
    const config = await loadConfig();
    
    console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证 - 多租户版)');
    console.log('📋 工作流 ID:', config.COZE_WORKFLOW_ID);

    // 新增：显示用户信息
    console.log('👤 用户信息:');
    console.log('   用户ID:', user.user_id);
    console.log('   用户名:', user.user_name);
    console.log('   API Key:', user.user_api_key.substring(0, 10) + '...');
    console.log('   套餐类型:', user.plan);
    console.log('   创建时间:', user.created_at);

    const accessToken = await getValidAccessToken();
    console.log('✅ Access Token 准备就绪');

    // 新增：丰富参数，添加用户信息
    const enrichedParams = {
      ...params,
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
    console.log('   User_API_Key:', enrichedParams.user_context.User_API_Key.substring(0, 10) + '...');
    console.log('   UserName:', enrichedParams.user_context.UserName);
    console.log('   Source:', enrichedParams.user_context.Source);
    console.log('   Timestamp:', enrichedParams.user_context.Timestamp);
    console.log('   UserPlan:', enrichedParams.user_context.UserPlan);
    console.log('   CreatedAt:', enrichedParams.user_context.CreatedAt);

    const startTime = Date.now();

    const response = await axios.post(
      'https://api.coze.cn/v1/workflow/run',
      {
        workflow_id: config.COZE_WORKFLOW_ID,
        parameters: enrichedParams,
        is_async: false,
      },
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        timeout: 30000,
      }
    );

    const duration = Date.now() - startTime;
    console.log('✅ 工作流调用成功');
    console.log(`📊 执行耗时: ${duration}ms`);
    console.log('📋 响应状态:', response.status);
    console.log('📋 响应数据:', JSON.stringify(response.data, null, 2));

    return response.data;

  } catch (error) {
    console.error('❌ 工作流调用失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);

      if (error.response.status === 401) {
        console.warn('⚠️  Token 可能已过期，清除缓存');
        cachedToken.accessToken = null;
        cachedToken.expiresAt = 0;

        console.log('🔄 重试一次...');
        return await callCozeWorkflow(params, user);
      }
    }

    throw error;
  }
}

// ============================================================================
// EdgeOne API 入口
// ============================================================================

export default async function handler(request, context) {
  console.log('🎯 API 调用开始');
  console.log('📋 请求方法:', request.method);
  console.log('📋 请求路径:', request.url);

  // 显示配置状态
  try {
    const config = await loadConfig();
    console.log('🔍 配置检查:', {
      COZE_JWT_OAUTH_CLIENT_ID: config.COZE_JWT_OAUTH_CLIENT_ID?.substring(0, 10) + '...',
      COZE_JWT_OAUTH_PUBLIC_KEY_ID: config.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
      COZE_WORKFLOW_ID: config.COZE_WORKFLOW_ID,
      使用Base64私钥: !!config.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
      使用原始私钥: !!config.COZE_JWT_OAUTH_PRIVATE_KEY,
      会话隔离: !!config.COZE_JWT_SESSION_NAME,
      用户配置: !!config.USERS_CONFIG,
    });
  } catch (error) {
    console.error('❌ 配置检查失败:', error.message);
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({
      success: false,
      error: 'Method not allowed'
    }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // 新增：多租户用户验证
    const user = await validateUserCall(request);

    // 解析请求体
    const reqBody = await request.json();
    
    // 新增：传递用户信息到工作流
    const result = await callCozeWorkflow(reqBody.params || {}, user);

    console.log('🎉 API 调用成功');

    return new Response(JSON.stringify({
      success: true,
      data: result,
      user: {
        user_id: user.user_id,
        user_name: user.user_name,
        plan: user.plan
      },
      authMethod: 'OAuth JWT (Multi-Tenant + Final v2 Debug)',
      tokenInfo: {
        expiresAt: new Date(cachedToken.expiresAt).toISOString(),
        remainingSeconds: Math.max(0, Math.floor((cachedToken.expiresAt - Date.now()) / 1000)),
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (err) {
    console.error('💥 API 调用失败:', err.message);

    return new Response(JSON.stringify({
      success: false,
      error: err.message,
      authMethod: 'OAuth JWT (Multi-Tenant + Final v2 Debug)',
      details: err.response?.data || null,
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ============================================================================
// 本地测试代码
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🧪 本地测试模式（多租户版）');

  // 设置测试环境变量
  process.env.TENCENT_COS_SECRET_ID = 'your-cos-secret-id';
  process.env.TENCENT_COS_SECRET_KEY = 'your-cos-secret-key';
  process.env.TENCENT_COS_BUCKET = 'your-bucket-name';
  process.env.TENCENT_COS_REGION = 'ap-guangzhou';

  // 模拟测试用户配置
  appConfig = {
    COZE_JWT_OAUTH_CLIENT_ID: 'your_client_id',
    COZE_JWT_OAUTH_PUBLIC_KEY_ID: 'your_public_key_id',
    COZE_JWT_OAUTH_PRIVATE_KEY_BASE64: 'your_base64_private_key',
    COZE_WORKFLOW_ID: '7620670520015700019',
    USERS_CONFIG: JSON.stringify({
      users: {
        'user_secret_token_test123': {
          user_id: 'user_test_001',
          user_name: '测试用户',
          plan: 'free',
          created_at: '2026-03-31T11:46:00Z'
        }
      }
    })
  };

  // 新增：测试用户验证
  try {
    const mockRequest = {
      headers: new Headers({
        'user-api-key': 'user_secret_token_test123'
      }),
      method: 'POST',
      url: '/test'
    };

    const user = await validateUserCall(mockRequest);
    console.log('✅ 用户验证测试通过');
    console.log('👤 验证后的用户信息:', user);

    await generateJWT().catch(console.error);
    await callCozeWorkflow({ test: 'data' }, user).catch(console.error);
  } catch (error) {
    console.error('❌ 测试失败:', error.message);
  }
}