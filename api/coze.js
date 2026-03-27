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

// 获取 Coze Access Token
async function getCozeAccessToken() {
  try {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,
      aud: 'api.coze.cn',
      iat: now,
      exp: now + 3600,
      jti: generateRandomString(32),
    };

    // 导入私钥（jose 标准写法）
    const privateKey = await importPKCS8(
      process.env.COZE_JWT_OAUTH_PRIVATE_KEY,
      'RS256'
    );

    // 签名 JWT
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
        typ: 'JWT',
      })
      .sign(privateKey);

    // ✅ 换取 Token（修复了请求头）
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
          // ❌ 这里原来的 Authorization 已删除
        },
      }
    );

    return tokenResponse.data.access_token;
  } catch (error) {
    console.error('获取Token失败:', error.response?.data || error.message);
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
      }
    );

    return response.data;
  } catch (error) {
    console.error('调用工作流失败:', error.response?.data || error.message);
    throw error;
  }
}

// Vercel API 入口
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const accessToken = await getCozeAccessToken();
    const result = await callCozeWorkflow(accessToken, req.body.params || {});

    return res.status(200).json({
      success: true,
      data: result,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message,
    });
  }
}