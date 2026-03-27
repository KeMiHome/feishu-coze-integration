import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

// 生成随机字符串
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 从 Base64 解码私钥
function decodePrivateKeyFromBase64(base64Key) {
  try {
    console.log('🔧 开始解码 Base64 私钥...');
    console.log('Base64 长度:', base64Key?.length);
    console.log('Base64 前100字符:', base64Key?.substring(0, 100));

    const decoded = Buffer.from(base64Key, 'base64').toString('utf-8');

    console.log('✅ 解码成功');
    console.log('解码后长度:', decoded?.length);
    console.log('解码后前100字符:', decoded?.substring(0, 100));
    console.log('以 BEGIN 开头:', decoded?.startsWith('-----BEGIN PRIVATE KEY-----'));
    console.log('以 END 结尾:', decoded?.endsWith('-----END PRIVATE KEY-----'));

    return decoded;
  } catch (error) {
    console.error('❌ Base64 解码失败:', error.message);
    throw new Error(`Failed to decode base64 private key: ${error.message}`);
  }
}

// 获取 Coze Access Token
async function getCozeAccessToken() {
  try {
    console.log('🚀 开始获取 Token');

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,
      aud: 'api.coze.cn',
      iat: now,
      exp: now + 3600,
      jti: generateRandomString(32),
    };

    console.log('📋 Payload:', { iss: payload.iss, aud: payload.aud });

    // 获取私钥 - 支持两种方式
    let privateKey;

    // 优先使用 Base64 编码的私钥（推荐方式）
    if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
      console.log('🔑 使用 Base64 编码的私钥');
      privateKey = decodePrivateKeyFromBase64(process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64);
    }
    // 回退到原始私钥（可能有问题的方式）
    else if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
      console.log('🔑 使用原始私钥（可能有问题）');
      privateKey = process.env.COZE_JWT_OAUTH_PRIVATE_KEY;

      // 尝试修复转义问题
      if (privateKey.includes('\\n')) {
        console.log('⚠️  检测到转义问题，尝试修复...');
        privateKey = privateKey.replace(/\\n/g, '\n');
      }
    } else {
      throw new Error('未找到私钥环境变量');
    }

    // 验证私钥格式
    if (!privateKey?.startsWith('-----BEGIN PRIVATE KEY-----')) {
      throw new Error(`私钥开头错误: ${privateKey?.substring(0, 50)}`);
    }

    if (!privateKey?.endsWith('-----END PRIVATE KEY-----')) {
      throw new Error(`私钥结尾错误: ${privateKey?.substring(privateKey?.length - 50)}`);
    }

    console.log('✅ 私钥格式验证通过');

    // 导入私钥
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

    console.log('✅ JWT 生成成功，长度:', jwt.length);

    // 换取 Token
    console.log('📡 开始换取 Token...');
    const tokenResponse = await axios.post(
      'https://api.coze.cn/api/permission/oauth2/token',
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
        ttl: 3600,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 10000,
      }
    );

    console.log('✅ Token 获取成功');
    return tokenResponse.data.access_token;
  } catch (error) {
    console.error('❌ 获取 Token 失败:', error.message);

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('响应数据:', error.response.data);
    }

    throw error;
  }
}

// 调用 Coze 工作流
async function callCozeWorkflow(accessToken, params) {
  try {
    const response = await axios.post(
      'https://api.coze.cn/v1/workflow/run',
      {
        workflow_id: process.env.COZE_WORKFLOW_ID,
        parameters: params,
        is_async: false,
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        timeout: 10000,
      }
    );
    return response.data;
  } catch (error) {
    console.error('❌ 调用工作流失败:', error.response?.data || error.message);
    throw error;
  }
}

// Vercel API 入口
export default async function handler(req, res) {
  console.log('🎯 API 调用开始');
  console.log('环境变量检查:', {
    COZE_JWT_OAUTH_CLIENT_ID: process.env.COZE_JWT_OAUTH_CLIENT_ID?.substring(0, 10) + '...',
    COZE_JWT_OAUTH_PUBLIC_KEY_ID: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
    COZE_WORKFLOW_ID: process.env.COZE_WORKFLOW_ID,
    使用Base64私钥: !!process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64,
    使用原始私钥: !!process.env.COZE_JWT_OAUTH_PRIVATE_KEY,
  });

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const accessToken = await getCozeAccessToken();
    const result = await callCozeWorkflow(accessToken, req.body.params || {});

    console.log('🎉 API 调用成功');
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('💥 API 调用失败:', err.message);

    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
}
