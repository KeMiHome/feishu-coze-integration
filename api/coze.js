import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// ============================================================================
// Coze OAuth JWT - 问题修复版本
// ============================================================================
// 发现的问题：
// 1. ❌ 参数名错误：使用 'duration' 而不是 'duration_seconds'
// 2. ❌ 缺少环境变量验证
// 3. ❌ 请求体记录不够详细
//
// 根据官方文档修复：
// - duration -> duration_seconds
// - 增加环境变量验证
// - 增加请求体完整记录
// ============================================================================

/**
 * JWT Token 缓存
 */
let cachedToken = {
  accessToken: null,
  expiresAt: 0,
};

/**
 * 验证环境变量
 */
function validateEnvironment() {
  const required = [
    'COZE_JWT_OAUTH_CLIENT_ID',
    'COZE_JWT_OAUTH_PUBLIC_KEY_ID',
    'COZE_WORKFLOW_ID',
  ];

  const optional = [
    'COZE_JWT_OAUTH_PRIVATE_KEY_BASE64',
    'COZE_JWT_OAUTH_PRIVATE_KEY',
    'COZE_JWT_SESSION_NAME',
  ];

  const errors = [];

  for (const key of required) {
    if (!process.env[key]) {
      errors.push(`缺少必需的环境变量: ${key}`);
    }
  }

  if (!process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 && !process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
    errors.push('至少需要配置 COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 或 COZE_JWT_OAUTH_PRIVATE_KEY 其中之一');
  }

  if (errors.length > 0) {
    throw new Error(errors.join('\n'));
  }

  console.log('✅ 环境变量验证通过');
  return true;
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
function getPrivateKey() {
  let privateKey;
  let keySource;

  if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
    keySource = 'Base64编码';
    privateKey = Buffer.from(
      process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
      'base64'
    ).toString('utf-8');
  } else if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
    keySource = '原始字符串';
    privateKey = process.env.COZE_JWT_OAUTH_PRIVATE_KEY;

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

    console.log('📋 JWT Payload:');
    console.log('   iss:', payload.iss);
    console.log('   aud:', payload.aud);
    console.log('   iat:', payload.iat, `(${new Date(payload.iat * 1000).toISOString()})`);
    console.log('   exp:', payload.exp, `(${new Date(payload.exp * 1000).toISOString()})`);
    console.log('   iat类型:', typeof payload.iat);
    console.log('   exp类型:', typeof payload.exp);
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
 *
 * 修复：
 * - duration -> duration_seconds (官方文档要求)
 */
async function getAccessTokenURLEncoded(jwt) {
  console.log('🔄 尝试方式 1: URL 编码格式（OAuth 2.0 标准）');

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', jwt);
  // params.append('duration_seconds', '86399'); // ✅ 修复：duration_seconds (24小时)

  console.log('📋 请求体（URL 编码）:');
  console.log('   grant_type:', params.get('grant_type'));
  console.log('   assertion长度:', params.get('assertion')?.length);
  console.log('   assertion前50字符:', params.get('assertion')?.substring(0, 50));
  console.log('   duration_seconds:', params.get('duration_seconds')); // ✅ 修复
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
 *
 * 修复：
 * - duration -> duration_seconds (官方文档要求)
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
  console.log('   duration_seconds:', requestBody.duration_seconds); // ✅ 修复
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

    // 验证环境变量
    validateEnvironment();

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
        console.error('   1. 检查 Vercel 日志中的完整请求体');
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
      authMethod: 'OAuth JWT (Final Fix v2)',
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
      authMethod: 'OAuth JWT (Final Fix v2)',
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
