import axios from 'axios';

// 调用 Coze 工作流 - 使用 Personal Access Token
async function callCozeWorkflow(params) {
  try {
    console.log('🎯 开始调用工作流 (PAT 方式)');

    const response = await axios.post(
      'https://api.coze.cn/v1/workflow/run',
      {
        workflow_id: process.env.COZE_WORKFLOW_ID,
        parameters: params,
        is_async: false,
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.COZE_PAT_TOKEN}`,
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
    console.error('❌ 调用工作流失败:', error.response?.data || error.message);
    throw error;
  }
}

// Vercel API 入口
export default async function handler(req, res) {
  console.log('🎯 API 调用开始 (PAT 方式)');
  console.log('📋 请求方法:', req.method);
  console.log('📋 请求体:', JSON.stringify(req.body));

  console.log('🔍 环境变量检查:', {
    COZE_PAT_TOKEN存在: !!process.env.COZE_PAT_TOKEN,
    COZE_WORKFLOW_ID: process.env.COZE_WORKFLOW_ID,
  });

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const result = await callCozeWorkflow(req.body.params || {});

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