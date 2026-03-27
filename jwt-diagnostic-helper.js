import axios from 'axios';
import { SignJWT, importPKCS8 } from 'jose';

/**
 * JWT 诊断工具
 *
 * 这个工具不直接调用 Coze API，而是帮助诊断：
 * 1. 环境变量是否正确配置
 * 2. 私钥是否能正确导入
 * 3. JWT 是否能正确生成
 * 4. JWT 格式是否符合标准
 *
 * 使用方法：
 * node jwt-diagnostic-helper.js
 */

console.log('🔍 Coze JWT 诊断工具');
console.log('='.repeat(50));

// ============================================================================
// 第一步：检查环境变量
// ============================================================================
console.log('\n📋 第一步：检查环境变量');
console.log('-'.repeat(30));

const envChecklist = [
  { name: 'COZE_JWT_OAUTH_CLIENT_ID', required: true },
  { name: 'COZE_JWT_OAUTH_PUBLIC_KEY_ID', required: true },
  { name: 'COZE_JWT_OAUTH_PRIVATE_KEY_BASE64', required: false },
  { name: 'COZE_JWT_OAUTH_PRIVATE_KEY', required: false },
  { name: 'COZE_WORKFLOW_ID', required: false },
];

let allEnvOK = true;

for (const item of envChecklist) {
  const value = process.env[item.name];
  const status = value ? '✅' : (item.required ? '❌' : '⚠️ ');

  console.log(`${status} ${item.name}:`, value ?
    (value.length > 20 ? value.substring(0, 20) + '...' : value) :
    '未设置');

  if (item.required && !value) {
    allEnvOK = false;
  }
}

if (!process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 && !process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
  console.log('❌ 至少需要配置 COZE_JWT_OAUTH_PRIVATE_KEY_BASE64 或 COZE_JWT_OAUTH_PRIVATE_KEY 其中之一');
  allEnvOK = false;
}

if (!allEnvOK) {
  console.log('\n❌ 环境变量检查失败，请先配置必要的环境变量');
  process.exit(1);
}

// ============================================================================
// 第二步：检查私钥
// ============================================================================
console.log('\n🔑 第二步：检查私钥');
console.log('-'.repeat(30));

let privateKey;
let keySource;

try {
  if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64) {
    keySource = 'Base64编码';
    privateKey = Buffer.from(process.env.COZE_JWT_OAUTH_PRIVATE_KEY_BASE64, 'base64').toString('utf-8');
  } else if (process.env.COZE_JWT_OAUTH_PRIVATE_KEY) {
    keySource = '原始字符串';
    privateKey = process.env.COZE_JWT_OAUTH_PRIVATE_KEY;

    // 检查是否有转义问题
    if (privateKey.includes('\\n')) {
      console.log('⚠️  检测到转义字符 \\n，尝试修复...');
      privateKey = privateKey.replace(/\\n/g, '\n');
      console.log('✅ 已修复转义字符');
    }
  } else {
    throw new Error('没有找到可用的私钥');
  }

  console.log(`📋 私钥来源: ${keySource}`);
  console.log(`📊 私钥长度: ${privateKey.length} 字符`);

  // 检查私钥格式
  const startsCorrectly = privateKey.startsWith('-----BEGIN PRIVATE KEY-----');
  const endsCorrectly = privateKey.endsWith('-----END PRIVATE KEY-----');
  const hasRSA = privateKey.includes('-----BEGIN');

  console.log('📋 格式检查:');
  console.log(`   ${startsCorrectly ? '✅' : '❌'} 以 -----BEGIN PRIVATE KEY----- 开头`);
  console.log(`   ${endsCorrectly ? '✅' : '❌'} 以 -----END PRIVATE KEY----- 结尾`);
  console.log(`   ${hasRSA ? '✅' : '❌'} 包含 RSA 私钥标记`);

  if (!startsCorrectly || !endsCorrectly) {
    console.log('\n❌ 私钥格式错误');
    console.log('💡 私钥必须包含完整的 BEGIN/END 标记');
    console.log('💡 示例格式:');
    console.log('   -----BEGIN PRIVATE KEY-----');
    console.log('   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...');
    console.log('   ...');
    console.log('   -----END PRIVATE KEY-----');
    process.exit(1);
  }

} catch (error) {
  console.log('\n❌ 私钥检查失败:', error.message);
  process.exit(1);
}

// ============================================================================
// 第三步：导入私钥
// ============================================================================
console.log('\n🔐 第三步：导入私钥');
console.log('-'.repeat(30));

let pkcs8Key;

try {
  pkcs8Key = await importPKCS8(privateKey, 'RS256');
  console.log('✅ 私钥导入成功');
  console.log('📋 算法: RS256');
  console.log('📋 类型:', pkcs8Key.constructor.name);
} catch (error) {
  console.log('❌ 私钥导入失败:', error.message);
  console.log('💡 可能的原因:');
  console.log('   1. 私钥不是 PKCS#8 格式');
  console.log('   2. 私钥已损坏或被篡改');
  console.log('   3. 私钥编码格式不正确');
  process.exit(1);
}

// ============================================================================
// 第四步：生成 JWT
// ============================================================================
console.log('\n🚀 第四步：生成 JWT');
console.log('-'.repeat(30));

let jwt;

try {
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: process.env.COZE_JWT_OAUTH_CLIENT_ID,
    aud: 'api.coze.cn',
    iat: now,
    exp: now + 3600,
    jti: crypto.getRandomValues(new Uint8Array(16)).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''),
  };

  console.log('📋 JWT Payload:');
  console.log('   iss:', payload.iss);
  console.log('   aud:', payload.aud);
  console.log('   iat:', payload.iat, `(${new Date(payload.iat * 1000).toISOString()})`);
  console.log('   exp:', payload.exp, `(${new Date(payload.exp * 1000).toISOString()})`);
  console.log('   iat类型:', typeof payload.iat);
  console.log('   exp类型:', typeof payload.exp);
  console.log('   jti:', payload.jti);

  jwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg: 'RS256',
      kid: process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID,
      typ: 'JWT',
    })
    .sign(pkcs8Key);

  console.log('✅ JWT 生成成功');
  console.log('📊 JWT 长度:', jwt.length, '字符');

} catch (error) {
  console.log('❌ JWT 生成失败:', error.message);
  process.exit(1);
}

// ============================================================================
// 第五步：验证 JWT 结构
// ============================================================================
console.log('\n🔍 第五步：验证 JWT 结构');
console.log('-'.repeat(30));

const parts = jwt.split('.');

if (parts.length !== 3) {
  console.log('❌ JWT 结构错误: 应该有 3 部分，实际有', parts.length, '部分');
  process.exit(1);
}

console.log('✅ JWT 结构正确 (3 部分: Header.Payload.Signature)');

const [headerB64, payloadB64, signatureB64] = parts;

console.log('📊 各部分长度:');
console.log('   Header:', headerB64.length, '字符');
console.log('   Payload:', payloadB64.length, '字符');
console.log('   Signature:', signatureB64.length, '字符');

// 尝试解码 Header
try {
  const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
  console.log('📋 Header 内容:', JSON.stringify(header, null, 2));

  if (header.alg !== 'RS256') {
    console.log('❌ Header 中的算法错误:', header.alg, '(应该是 RS256)');
  }

  if (header.typ !== 'JWT') {
    console.log('❌ Header 中的类型错误:', header.typ, '(应该是 JWT)');
  }

  if (header.kid !== process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID) {
    console.log('❌ Header 中的 kid 与环境变量不匹配');
  }

  console.log('✅ Header 验证通过');

} catch (error) {
  console.log('❌ Header 解析失败:', error.message);
}

// 尝试解码 Payload
try {
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
  console.log('📋 Payload 内容:');
  console.log('   iss:', payload.iss, `(${payload.iss === process.env.COZE_JWT_OAUTH_CLIENT_ID ? '✅' : '❌'})`);
  console.log('   aud:', payload.aud, `(${payload.aud === 'api.coze.cn' ? '✅' : '❌'})`);
  console.log('   iat:', payload.iat, `(类型: ${typeof payload.iat})`);
  console.log('   exp:', payload.exp, `(类型: ${typeof payload.exp})`);
  console.log('   jti:', payload.jti);

  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    console.log('❌ Payload 中的 iat/exp 类型错误 (应该是 number)');
  }

  if (payload.exp <= payload.iat) {
    console.log('❌ Payload 中的 exp 应该大于 iat');
  }

  console.log('✅ Payload 验证通过');

} catch (error) {
  console.log('❌ Payload 解析失败:', error.message);
}

// ============================================================================
// 第六步：检查是否有特殊字符
// ============================================================================
console.log('\n🔍 第六步：检查特殊字符');
console.log('-'.repeat(30));

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
  console.log('⚠️  发现非 ASCII 字符:', specialChars.length, '个');
  specialChars.forEach(item => {
    console.log(`   位置 ${item.index}: "${item.char}" (编码: ${item.code})`);
  });
} else {
  console.log('✅ 未发现非 ASCII 字符');
}

// ============================================================================
// 第七步：生成测试请求
// ============================================================================
console.log('\n📡 第七步：生成测试请求');
console.log('-'.repeat(30));

console.log('方式 1: URL 编码格式');
const paramsURL = new URLSearchParams();
paramsURL.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
paramsURL.append('assertion', jwt);
console.log('请求体长度:', paramsURL.toString().length, '字符');
console.log('assertion 字段长度:', paramsURL.get('assertion')?.length, '字符');

console.log('\n方式 2: JSON 格式');
const bodyJSON = {
  grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  assertion: jwt,
};
const jsonStr = JSON.stringify(bodyJSON);
console.log('请求体长度:', jsonStr.length, '字符');
console.log('JSON assertion 字段长度:', bodyJSON.assertion.length, '字符');

// ============================================================================
// 诊断总结
// ============================================================================
console.log('\n' + '='.repeat(50));
console.log('📊 诊断总结');
console.log('='.repeat(50));

const checks = [
  { name: '环境变量配置', status: allEnvOK },
  { name: '私钥格式', status: true },
  { name: '私钥导入', status: true },
  { name: 'JWT 生成', status: true },
  { name: 'JWT 结构', status: true },
  { name: '特殊字符检查', status: specialChars.length === 0 },
];

const passedCount = checks.filter(c => c.status).length;
const totalCount = checks.length;

checks.forEach(check => {
  console.log(`${check.status ? '✅' : '❌'} ${check.name}`);
});

console.log(`\n总计: ${passedCount}/${totalCount} 项通过`);

if (passedCount === totalCount) {
  console.log('\n✅ 本地诊断全部通过！');
  console.log('💡 这意味着 JWT 本身没有问题');
  console.log('💡 如果仍然失败，问题可能出在:');
  console.log('   1. Coze API 端的配置（公钥不匹配、应用未授权）');
  console.log('   2. 网络问题（防火墙、代理）');
  console.log('   3. Coze API 本身的问题');
  console.log('\n📋 下一步建议:');
  console.log('   1. 登录 Coze 控制台，重新上传公钥');
  console.log('   2. 在 OAuth 应用详情页点击"重新授权"');
  console.log('   3. 联系 Coze 技术支持，提供以下信息:');
  console.log('      - Client ID:', process.env.COZE_JWT_OAUTH_CLIENT_ID);
  console.log('      - Public Key ID:', process.env.COZE_JWT_OAUTH_PUBLIC_KEY_ID);
  console.log('      - 错误消息: "invalid jwt: empty jwt token"');
} else {
  console.log('\n❌ 本地诊断发现问题，请根据上述提示修复');
}
