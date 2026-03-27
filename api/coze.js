import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// ============================================================================
// Coze OAuth JWT - 终极修复版
// ============================================================================
// 🔥 核心发现：Coze 不使用标准的 OAuth 2.0 JWT Bearer 流程！
//
// 标准 OAuth 2.0 JWT Bearer 流程：
//   POST /oauth2/token
//   Body: grant_type=...&assertion=JWT
//
// Coze 实际使用的流程：
//   POST /oauth2/token
//   Header: Authorization: Bearer JWT
//   Body: grant_type=...&duration_seconds=...
//
// 这就是为什么一直报 "empty jwt token" 的原因！
// Coze 从 Authorization header 读取 JWT，而不是从 request body！
// ============================================================================

/**
 * JWT Token 缓存
 */
let cachedToken = {
  accessToken: null,
  expiresAt: 0,
};

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
 * 获取私钥
 */
function getPrivateKey() {
  let privateKey;

  if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
    console.log('🔑 使用 Base64 编码的私钥');
    privateKey = Buffer.from(
      process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
      'base64'
    ).toString('utf-8');
  } else if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
    console.log('🔑 使用原始私钥');
    privateKey = process.env.COZE_JWT_OAUTH_PRIVATE_KEY;
    if (privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }
  } else {
    throw new Error('未找到私钥环境变量');
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
 * 生成 JWT Token
 */
async function generateJWT() {
  try {
    console.log('🚀 开始生成 JWT');

    const now = Math.floor(Date.now() / 1000);

    const payload = {
      iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,
      aud: 'api.coze.cn',
      iat: now,
      exp: now + 3600,
      jti: generateRandomString(32),
    };

    if (process.env.COZE_JWT_SESSION_NAME) {
      payload.session_name = process.env.COZE_JWT_SESSION_NAME;
    }

    console.log('📋 JWT Payload:');
    console.log('   iss:', payload.iss);
    console.log('   aud:', payload.aud);
    console.log('   iat:', payload.iat);
    console.log('   exp:', payload.exp);
    console.log('   jti:', payload.jti);

    const privateKey = getPrivateKey();
    const pkcs8Key = await importPKCS8(privateKey, 'RS256');
    console.log('✅ 私钥导入成功');

    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
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

/**
 * 🔥 关键修复：使用 Coze 特有的认证方式
 * 将 JWT 放在 Authorization header，而不是请求体中
 */
async function getAccessTokenCozeWay(jwt) {
  console.log('🔄 使用 Coze 特有方式获取 Access Token');
  console.log('💡 JWT 通过 Authorization: Bearer {JWT} 传递');

  const requestBody = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    duration_seconds: 86399, // 可选：24小时有效期
  };

  console.log('📋 请求体:');
  console.log('   grant_type:', requestBody.grant_type);
  console.log('   duration_seconds:', requestBody.duration_seconds);

  const response = await axios.post(
    'https://api.coze.cn/api/permission/oauth2/token',
    requestBody,
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${jwt}`, // 🔥 关键：JWT 在 Header 中
      },
      timeout: 10000,
    }
  );

  console.log('✅ Access Token 获取成功！');
  console.log('📊 Token 过期时间:', new Date(response.data.expires_in * 1000).toISOString());

  return response.data;
}

/**
 * 获取 Access Token
 */
async function getAccessToken() {
  try {
    console.log('🚀 开始获取 Access Token');

    // 验证环境变量
    const required = [
      'COZE_JWT_OAUTH_CLIENT_ID',
      'COZE_JWT_OAUTH_PUBLIC_KEY_ID',
      'COZE_WORKFLOW_ID',
    ];

    for (const key of required) {
      if (!process.env[key]) {
        throw new Error(`缺少必需的环境变量: ${key}`);
      }
    }

    console.log('✅ 环境变量验证通过');

    // 生成 JWT
    const jwt = await generateJWT();

    // 使用 Coze 特有的认证方式
    return await getAccessTokenCozeWay(jwt);

  } catch (error) {
    console.error('❌ 获取 Access Token 失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);
      console.error('错误码:', error.response.data?.error_code);
      console.error('错误消息:', error.response.data?.error_message);
    }

    throw error;
  }
}

/**
 * 获取有效的 Access Token（带缓存）
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
  cachedToken.expiresAt = tokenResponse.expires_in * 1000;

  console.log('✅ Access Token 已缓存');
  console.log('📊 过期时间:', new Date(cachedToken.expiresAt).toISOString());

  return tokenResponse.access_token;
}

/**
 * 调用 Coze 工作流
 */
async function callCozeWorkflow(params) {
  try {
    console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证)');
    console.log('📋 工作流 ID:', process.env.COZE_WORKFLOW_ID);

    const accessToken = await getValidAccessToken();
    console.log('✅ Access Token 准备就绪');

    const startTime = Date.now();

    const response = await axios.post(
      'https://api.coze.cn/v1/workflow/run',
      {
        workflow_id: process.env.COZE_WORKFLOW_ID,
        parameters: params || {},
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
        return await callCozeWorkflow(params);
      }
    }

    throw error;
  }
}

// ============================================================================
// Vercel API 入口
// ============================================================================

export default async function handler(req, res) {
  console.log('🎯 API 调用开始');
  console.log('📋 请求方法:', req.method);
  console.log('📋 请求路径:', req.url);

  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  try {
    const result = await callCozeWorkflow(req.body.params || {});

    console.log('🎉 API 调用成功');

    return res.status(200).json({
      success: true,
      data: result,
      authMethod: 'OAuth JWT (Ultimate Fix - Coze Way)',
      tokenInfo: {
        expiresAt: new Date(cachedToken.expiresAt).toISOString(),
        remainingSeconds: Math.max(0, Math.floor((cachedToken.expiresAt - Date.now()) / 1000)),
      },
    });

  } catch (err) {
    console.error('💥 API 调用失败:', err.message);

    return res.status(500).json({
      success: false,
      error: err.message,
      authMethod: 'OAuth JWT (Ultimate Fix - Coze Way)',
      details: err.response?.data || null,
    });
  }
}

// ============================================================================
// 本地测试代码
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🧪 本地测试模式');

  process.env.COZE_JWT_OAUTH_CLIENT_ID = 'your_client_id';
  process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID = 'your_public_key_id';
  process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 = 'your_base64_private_key';
  process.env.COZE_WORKFLOW_ID = '7620670520015700019';

  await callCozeWorkflow({ test: 'data' }).catch(console.error);
}
