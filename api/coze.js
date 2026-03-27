import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// ============================================================================
// Coze OAuth JWT (开发者模式) - 修复版本
// ============================================================================
// 修复问题：
// - JWT Payload 中的 iat 和 exp 必须是数字（Unix 时间戳），不是字符串
// - 请求体中的 assertion 字段必须正确传递 JWT
// ============================================================================

/**
 * JWT Token 缓存
 */
let cachedToken = {
  accessToken: null,
  expiresAt: 0,
};

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

    if (privateKey && privateKey.includes('\\n')) {
      console.log('⚠️  检测到转义问题，尝试修复...');
      privateKey = privateKey.replace(/\\n/g, '\n');
    }
  } else {
    throw new Error('未找到私钥环境变量');
  }

  if (!privateKey?.startsWith('-----BEGIN PRIVATE KEY-----')) {
    throw new Error(`私钥开头错误: ${privateKey?.substring(0, 50)}`);
  }

  if (!privateKey?.endsWith('-----END PRIVATE KEY-----')) {
    throw new Error(`私钥结尾错误: ${privateKey?.substring(privateKey?.length - 50)}`);
  }

  console.log('✅ 私钥格式验证通过');
  return privateKey;
}

/**
 * 生成 JWT Token（修复版本）
 *
 * 关键修复：
 * - iat 和 exp 必须是数字，不是字符串
 * - 确保 JWT 格式完全符合 Coze API 要求
 */
async function generateJWT() {
  try {
    console.log('🚀 开始生成 JWT');

    const now = Math.floor(Date.now() / 1000);

    // ⚠️ 关键修复：iat 和 exp 必须是数字
    const payload = {
      iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,      // 字符串
      aud: 'api.coze.cn',                             // 字符串
      iat: now,                                       // 数字（Unix 时间戳）
      exp: now + 3600,                                // 数字（Unix 时间戳）
      jti: generateRandomString(32),                   // 字符串
    };

    // 可选：设置会话隔离
    if (process.env.COZE_JWT_SESSION_NAME) {
      payload.session_name = process.env.COZE_JWT_SESSION_NAME;
      console.log('🔐 会话隔离已启用，session_name:', process.env.COZE_JWT_SESSION_NAME);
    }

    console.log('📋 JWT Payload:', {
      iss: payload.iss,
      aud: payload.aud,
      iat: payload.iat,           // 数字
      iat_type: typeof payload.iat, // 应该是 'number'
      exp: payload.exp,           // 数字
      exp_type: typeof payload.exp, // 应该是 'number'
      jti: payload.jti,
      hasSessionName: !!process.env.COZE_JWT_SESSION_NAME,
    });

    // 获取私钥
    const privateKey = getPrivateKey();

    // 导入私钥（PKCS8 格式）
    const pkcs8Key = await importPKCS8(privateKey, 'RS256');
    console.log('✅ 私钥导入成功');

    // 签名 JWT
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
        typ: 'JWT',
      })
      .sign(pkcs8Key);

    console.log('✅ JWT 生成成功');
    console.log('📊 JWT 长度:', jwt.length);
    console.log('🔑 JWT 前100字符:', jwt.substring(0, 100));

    // 验证 JWT 结构（三部分用 . 分隔）
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error(`JWT 格式错误，应该有 3 部分，实际有 ${parts.length} 部分`);
    }
    console.log('✅ JWT 结构验证通过（Header.Payload.Signature）');

    return jwt;

  } catch (error) {
    console.error('❌ JWT 生成失败:', error.message);
    throw error;
  }
}

/**
 * 获取 Access Token（使用 JWT）
 */
async function getAccessToken() {
  try {
    console.log('🚀 开始获取 Access Token');

    // 生成 JWT
    const jwt = await generateJWT();

    // ⚠️ 关键修复：确保 assertion 字段正确传递 JWT
    console.log('📡 使用官方推荐的 JSON 格式请求');
    console.log('📋 请求体:', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion长度: jwt.length,
      assertion前50字符: jwt.substring(0, 50),
      duration: 3600,
    });

    const response = await axios.post(
      'https://api.coze.cn/api/permission/oauth2/token',
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,  // ⚠️ 确保 JWT 直接传递，不是字符串化
        duration: 3600,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        timeout: 10000,
      }
    );

    console.log('✅ Access Token 获取成功');
    console.log('📋 响应状态:', response.status);
    console.log('📊 Token 有效期:', response.data.expires_in, '秒');

    return response.data;

  } catch (error) {
    console.error('❌ 获取 Access Token 失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);

      const errorCode = error.response.data.error_code;
      const errorMessage = error.response.data.error_message;

      console.error('错误码:', errorCode);
      console.error('错误消息:', errorMessage);

      switch (errorCode) {
        case 'invalid_client':
          console.error('💡 原因：客户端认证失败');
          console.error('💡 错误详情:', errorMessage);
          console.error('💡 可能原因：');
          console.error('   1. Client ID (iss) 不正确');
          console.error('   2. Public Key ID (kid) 不正确');
          console.error('   3. 私钥与公钥不匹配');
          console.error('   4. JWT 格式错误');
          console.error('   5. JWT iat/exp 不是数字');
          console.error('   6. OAuth 应用未完成授权');
          console.error('💡 解决步骤：');
          console.error('   1. 检查 COZE_JWT_OAUTH_CLIENT_ID');
          console.error('   2. 检查 COZE_JWT_OAUTH_PUBLIC_KEY_ID');
          console.error('   3. 确认私钥格式和完整性');
          console.error('   4. 检查 JWT Payload 中的 iat/exp 是否为数字');
          console.error('   5. 在 OAuth 应用详情页点击"授权"');
          break;

        case 'invalid_grant':
          console.error('💡 原因：JWT 授权失败');
          console.error('💡 错误详情:', errorMessage);
          console.error('💡 可能原因：');
          console.error('   1. JWT 签名验证失败');
          console.error('   2. JWT 已过期');
          console.error('   3. JWT 格式错误');
          console.error('   4. JWT assertion 字段未正确传递');
          break;

        case 'access_denied':
          console.error('💡 原因：访问被拒绝');
          console.error('💡 错误详情:', errorMessage);
          console.error('💡 可能原因：');
          console.error('   1. OAuth 应用权限不足');
          console.error('   2. OAuth 应用未授权访问该工作空间');
          console.error('   3. 工作流不存在');
          break;

        default:
          console.error('💡 未知错误');
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

  // 检查缓存是否有效（提前 30 秒刷新）
  if (cachedToken.accessToken && cachedToken.expiresAt > now + 30000) {
    console.log('✅ 使用缓存的 Access Token');
    console.log('📊 距离过期还有:', Math.floor((cachedToken.expiresAt - now) / 1000), '秒');
    return cachedToken.accessToken;
  }

  // 缓存无效或即将过期，获取新 Token
  console.log('🔄 缓存失效，获取新的 Access Token');

  const tokenResponse = await getAccessToken();

  // 更新缓存
  cachedToken.accessToken = tokenResponse.access_token;
  cachedToken.expiresAt = now + tokenResponse.expires_in * 1000;

  console.log('✅ Access Token 已缓存');
  console.log('📊 过期时间:', new Date(cachedToken.expiresAt).toISOString());

  return tokenResponse.access_token;
}

/**
 * 调用 Coze 工作流（使用 OAuth JWT）
 */
async function callCozeWorkflow(params) {
  try {
    console.log('🎯 开始调用 Coze 工作流 (OAuth JWT 认证)');
    console.log('📋 工作流 ID:', process.env.COZE_WORKFLOW_ID);

    // 获取有效的 Access Token
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
    console.log('📋 响应状态:', response.status);
    console.log('📋 响应数据:', JSON.stringify(response.data, null, 2));

    return response.data;

  } catch (error) {
    console.error('❌ 工作流调用失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);

      // 如果是 401 错误，可能是 Token 过期，清除缓存重试
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

  // 环境变量检查
  console.log('🔍 环境变量检查:', {
    COZE_JWT_OAUTH_CLIENT_ID: process.env.COZE_JWT_OAUTH_CLIENT_ID?.substring(0, 10) + '...',
    COZE_JWT_OAUTH_PUBLIC_KEY_ID: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
    COZE_WORKFLOW_ID: process.env.COZE_WORKFLOW_ID,
    使用Base64私钥: !!process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
    使用原始私钥: !!process.env.COZE_JWT_OAUTH_PRIVATE_KEY,
    会话隔离: !!process.env.COZE_JWT_SESSION_NAME,
  });

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
      authMethod: 'OAuth JWT (Fixed)',
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
      authMethod: 'OAuth JWT (Fixed)',
      details: err.response?.data || null,
    });
  }
}

// ============================================================================
// 本地测试代码
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🧪 本地测试模式');

  // 模拟 Vercel 环境变量
  process.env.COZE_JWT_OAUTH_CLIENT_ID = 'your_client_id';
  process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID = 'your_public_key_id';
  process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 = 'your_base64_private_key';
  process.env.COZE_WORKFLOW_ID = '7620670520015700019';

  // 测试 JWT 生成
  await generateJWT().catch(console.error);

  // 测试调用
  await callCozeWorkflow({
    test: 'data',
  }).catch(console.error);
}
