// 用于测试腾讯COS存储桶访问是否正常

import axios from 'axios';
import COS from 'cos-nodejs-sdk-v5';

// 加载环境变量
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

const cos = new COS({
  SecretId: process.env.TENCENT_COS_SECRET_ID,
  SecretKey: process.env.TENCENT_COS_SECRET_KEY,
  Region: process.env.TENCENT_COS_REGION || 'ap-guangzhou'
});

async function testConfigLoad() {
  try {
    console.log('🔍 开始测试 COS 配置加载...');

    // 验证环境变量
    const requiredEnvVars = [
      'TENCENT_COS_SECRET_ID',
      'TENCENT_COS_SECRET_KEY',
      'TENCENT_COS_BUCKET',
      'TENCENT_COS_REGION'
    ];

    const missingVars = requiredEnvVars.filter(key => !process.env[key]);
    if (missingVars.length > 0) {
      console.error('❌ 缺少环境变量:', missingVars);
      return false;
    }

    console.log('✅ 所有环境变量已配置');
    console.log('📊 存储桶:', process.env.TENCENT_COS_BUCKET);
    console.log('📊 地域:', process.env.TENCENT_COS_REGION);

    // 测试获取 secrets.json
    try {
      const secretsResult = await cos.getObject({
        Bucket: process.env.TENCENT_COS_BUCKET,
        Region: process.env.TENCENT_COS_REGION,
        Key: 'config/secrets.json'
      });

      const secrets = JSON.parse(secretsResult.Body.toString());
      console.log('✅ secrets.json 加载成功');
      console.log('📊 secrets.json 配置项数量:', Object.keys(secrets).length);
    } catch (error) {
      console.error('❌ secrets.json 加载失败:', error.message);
    }

    // 测试获取 config.json
    try {
      const configResult = await cos.getObject({
        Bucket: process.env.TENCENT_COS_BUCKET,
        Region: process.env.TENCENT_COS_REGION,
        Key: 'config/config.json'
      });

      const config = JSON.parse(configResult.Body.toString());
      console.log('✅ config.json 加载成功');
      console.log('📊 config.json 配置项数量:', Object.keys(config).length);
    } catch (error) {
      console.error('❌ config.json 加载失败:', error.message);
    }

    return true;

  } catch (error) {
    console.error('❌ COS 配置测试失败:', error.message);
    return false;
  }
}

testConfigLoad();