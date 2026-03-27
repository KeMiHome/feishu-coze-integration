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
    const decoded = Buffer.from(base64Key, 'base64').toString('utf-8');
    console.log('✅ Base64 解码成功，长度:', decoded?.length);
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

    // 获取私钥 - 优先使用 Base64 编码的私钥
    let privateKey;

    if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
      console.log('🔑 使用 Base64 编码的私钥');
      privateKey = decodePrivateKeyFromBase64(process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64);
    } else if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
      console.log('🔑 使用原始私钥');
      privateKey = process.env.COZE_JWT_OAUTH_PRIVATE_KEY;
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
    console.log('JWT 前100字符:', jwt.substring(0, 100));

    // 换取 Token - 尝试不同的请求格式
    console.log('📡 开始尝试不同的请求格式...');

    // 方法 1: URL 编码格式 (最常见)
    try {
      console.log('🔄 尝试方式 1: URL 编码格式 (最常用)');
      const params = new URLSearchParams();
      params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
      params.append('assertion', jwt);
      params.append('ttl', '3600');

      console.log('请求数据:', {
        grant_type: params.get('grant_type'),
        assertion长度: params.get('assertion')?.length,
        assertion前50字符: params.get('assertion')?.substring(0, 50),
        ttl: params.get('ttl')
      });

      const tokenResponse = await axios.post(
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

      console.log('响应状态:', tokenResponse.status);
      console.log('响应数据:', tokenResponse.data);

      if (tokenResponse.data.access_token) {
        console.log('✅ 方式 1 成功！Token 获取成功');
        return tokenResponse.data.access_token;
      }
    } catch (error1) {
      console.log('❌ 方式 1 失败:', error1.response?.data?.error || error1.message);
    }

    // 方法 2: 标准 JSON 格式
    try {
      console.log('🔄 尝试方式 2: 标准 JSON 格式');
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
            'Accept': 'application/json',
          },
          timeout: 10000,
        }
      );

      if (tokenResponse.data.access_token) {
        console.log('✅ 方式 2 成功！Token 获取成功');
        return tokenResponse.data.access_token;
      }
    } catch (error2) {
      console.log('❌ 方式 2 失败:', error2.response?.data?.error || error2.message);
    }

    throw new Error('所有 Token 获取方式都失败');

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
    console.log('🎯 开始调用工作流');

    console.log('📋 Workflow ID:', process.env.COZE_WORKFLOW_ID);
    console.log('📋 Token 存在:', !!accessToken);
    console.log('📋 Token 长度:', accessToken?.length);

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
          'Accept': 'application/json',
        },
        timeout: 10000,
      }
    );

    console.log('✅ 工作流调用成功，状态:', response.status);
    console.log('📋 响应数据:', response.data);

    return response.data;
  } catch (error) {
    console.error('❌ 调用工作流失败:', error.message);

    if (error.response) {
      console.error('HTTP 状态码:', error.response.status);
      console.error('响应数据:', error.response.data);
    }

    throw error;
  }
}

// Vercel API 入口
export default async function handler(req, res) {
  console.log('🎯 API 调用开始');
  console.log('📋 请求方法:', req.method);
  console.log('📋 请求体:', JSON.stringify(req.body));

  console.log('🔍 环境变量检查:', {
    COZE_JWT_OAUTH_CLIENT_ID: process.env.COZE_JWT_OAUTH_CLIENT_ID,
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
