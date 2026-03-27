import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// ============================================================================
// Coze OAuth JWT (开发者模式) - 最终修复版本
// ============================================================================
// 问题分析：
// - JWT 格式已经正确（iat/exp 都是数字）
// - 但 Coze 仍然报 "invalid jwt: empty jwt token"
// - 这说明问题在请求体的传递方式上
//
// 可能原因：
// 1. Coze 期望的是 URL 编码格式，不是 JSON 格式
// 2. assertion 字段可能被错误转义或编码
// 3. JWT 本身可能包含 Coze 不支持的字符
//
// 解决方案：
// - 尝试两种请求格式：URL 编码和 JSON
// - 增强日志，输出完整的请求体
// - 验证 JWT 的完整性
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
  console.log('📊 私钥长度:', privateKey.length);
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
      console.log('🔐 会话隔离已启用');
    }

    console.log('📋 JWT Payload:', {
      iss: payload.iss,
      aud: payload.aud,
      iat: payload.iat,
      iat_type: typeof payload.iat,
      exp: payload.exp,
      exp_type: typeof payload.exp,
      jti: payload.jti,
    });

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
    console.log('📊 JWT 长度:', jwt.length);

    // 验证 JWT 结构
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error(`JWT 格式错误：应该有 3 部分，实际有 ${parts.length} 部分`);
    }
    console.log('✅ JWT 结构验证通过');

    // 验证每一部分的长度
    console.log('📊 JWT 各部分长度:', {
      header: parts[0].length,
      payload: parts[1].length,
      signature: parts[2].length,
    });

    return jwt;

  } catch (error) {
    console.error('❌ JWT 生成失败:', error.message);
    throw error;
  }
}

/**
 * 使用 URL 编码格式获取 Access Token
 *
 * 这是 OAuth 2.0 的标准格式，Coze 可能期望这种格式
 */
async function getAccessTokenURLEncoded(jwt) {
  console.log('🔄 尝试方式 1: URL 编码格式（OAuth 2.0 标准）');

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', jwt);
  params.append('duration', '3600');

  console.log('📋 请求体（URL 编码）:');
  console.log('   grant_type:', params.get('grant_type'));
  console.log('   assertion长度:', params.get('assertion')?.length);
  console.log('   assertion前50字符:', params.get('assertion')?.substring(0, 50));
  console.log('   duration:', params.get('duration'));

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
 *
 * 这是现代 API 的常用格式
 */
async function getAccessTokenJSON(jwt) {
  console.log('🔄 尝试方式 2: JSON 格式');

  const requestBody = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
    duration: 3600,
  };

  console.log('📋 请求体（JSON）:');
  console.log('   grant_type:', requestBody.grant_type);
  console.log('   assertion长度:', requestBody.assertion?.length);
  console.log('   assertion前50字符:', requestBody.assertion?.substring(0, 50));
  console.log('   duration:', requestBody.duration);

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

    // 生成 JWT
    const jwt = await generateJWT();

    // 先尝试 URL 编码格式（OAuth 2.0 标准）
    try {
      return await getAccessTokenURLEncoded(jwt);
    } catch (error1) {
      console.log('❌ 方式 1 失败:', error1.response?.data?.error || error1.message);

      // 如果 URL 编码失败，尝试 JSON 格式
      try {
        return await getAccessTokenJSON(jwt);
      } catch (error2) {
        console.log('❌ 方式 2 失败:', error2.response?.data?.error || error2.message);

        // 两种方式都失败，抛出错误
        throw new Error('所有 Token 获取方式都失败');
      }
    }

  } catch (error) {
    console.error('❌ 获取 Access Token 失败');

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('错误详情:', error.response.data);

      const errorCode = error.response.data.error_code || error.response.data.code;
      const errorMessage = error.response.data.error_message || error.response.data.msg;

      console.error('错误码:', errorCode);
      console.error('错误消息:', errorMessage);

      if (errorMessage?.includes('empty jwt')) {
        console.error('💡 特殊错误：JWT 被识别为空');
        console.error('💡 可能原因：');
        console.error('   1. JWT 包含特殊字符导致解析失败');
        console.error('   2. JWT 格式不符合 Coze 期望');
        console.error('   3. assertion 字段未正确传递');
        console.error('💡 建议：');
        console.error('   1. 检查 JWT 是否包含非 ASCII 字符');
        console.error('   2. 尝试重新生成密钥对');
        console.error('   3. 联系 Coze 技术支持');
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
      authMethod: 'OAuth JWT (Ultimate Fix)',
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
      authMethod: 'OAuth JWT (Ultimate Fix)',
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

  await generateJWT().catch(console.error);
  await callCozeWorkflow({ test: 'data' }).catch(console.error);
}
