const axios = require('axios');
const { SignJWT } = require('jose');

/**
 * 导入私钥
 */
async function importKey(privateKeyPem) {
  const crypto = require('crypto');
  return crypto.createPrivateKey(privateKeyPem);
}

/**
 * 生成随机字符串（用于jti）
 */
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * 获取Coze Access Token
 */
async function getCozeAccessToken() {
  try {
    // 1. 准备JWT payload
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,
      aud: 'api.coze.cn',
      iat: now,
      exp: now + 3600,
      jti: generateRandomString(32),
    };

    // 2. 使用私钥签名JWT
    const privateKey = await importKey(process.env.COZE_JWT_OAUTH_PRIVATE_KEY);
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
        typ: 'JWT'
      })
      .sign(privateKey);

    // 3. 用JWT换取Access Token
    const tokenResponse = await axios.post(
      'https://api.coze.cn/api/permission/oauth2/token',
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
        ttl: 3600
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${jwt}`
        }
      }
    );

    return tokenResponse.data.access_token;

  } catch (error) {
    console.error('获取Coze Access Token失败:', error.response?.data || error.message);
    throw error;
  }
}

/**
 * 调用Coze工作流
 */
async function callCozeWorkflow(accessToken, params) {
  try {
    const response = await axios.post(
      `https://api.coze.cn/v1/workflow/run`,
      {
        workflow_id: process.env.COZE_WORKFLOW_ID,
        parameters: params,
        is_async: false
      },
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;

  } catch (error) {
    console.error('调用Coze工作流失败:', error.response?.data || error.message);
    throw error;
  }
}

/**
 * Vercel API路由处理函数
 */
export default async function handler(req, res) {
  // 只允许POST请求
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log('收到请求:', req.body);

    // 1. 获取Coze Access Token
    const accessToken = await getCozeAccessToken();
    console.log('获取到Access Token');

    // 2. 调用Coze工作流
    const workflowResult = await callCozeWorkflow(accessToken, req.body.params || {});
    console.log('工作流执行结果:', workflowResult);

    // 3. 返回结果
    return res.status(200).json({
      success: true,
      data: workflowResult
    });

  } catch (error) {
    console.error('处理失败:', error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}