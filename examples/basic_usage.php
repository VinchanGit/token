<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */
require_once __DIR__ . '/../vendor/autoload.php';

use Vinchan\Token\Token;

// 基本使用示例

// 1. 创建一个简单的JWT Token
$secret = 'your-secret-key-here';
$payload = [
    'user_id' => 123,
    'username' => 'john_doe',
    'email' => 'john@example.com',
];

$token = Token::create()
    ->withPayload($payload)
    ->withExpiration(3600) // 1小时后过期
    ->withIssuer('my-app')
    ->withAudience('my-users')
    ->sign($secret, 'HS256');

echo 'Generated Token: ' . $token . "\n\n";

// 2. 解析和验证Token
try {
    $parser = Token::parse($token)->verify($secret, 'HS256');

    echo "Token is valid!\n";
    echo 'User ID: ' . $parser->getClaim('user_id') . "\n";
    echo 'Username: ' . $parser->getClaim('username') . "\n";
    echo 'Email: ' . $parser->getClaim('email') . "\n";
    echo 'Issuer: ' . $parser->getClaim('iss') . "\n";
    echo 'Audience: ' . $parser->getClaim('aud') . "\n";
    echo 'Expires at: ' . date('Y-m-d H:i:s', $parser->getClaim('exp')) . "\n";
} catch (Exception $e) {
    echo 'Token validation failed: ' . $e->getMessage() . "\n";
}

// 3. 使用不同的算法
echo "\n--- RSA Example ---\n";

// 生成RSA密钥对（实际使用中应该预先生成）
$rsaPrivateKey = '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuqlAJ7DC8drlmKbpVAxS+vmAw02d7VVgXMPOKunElE1YSh0u
1PhzIVTJVh4wVk0cJZhE9fyg+1mGwCejSjNmn5SXncfKBVdaX+WEDt7UYpjbcyiM
X2SsNDxapXOwKtjw5q47Z61lEBpdaW5xerBhyuUdprqyAholdsOxZbRo+jevaXnW
gvZhsNZmIGvQeF9aEoXLn6bg6u692om6odnO4rN/nRRqyx655soTGkkj8Sr1Xova
GTR4m1Fq3RumPx37Cp14Mr4zaRgt/GxcMXERE4ug3amBJ53qN91NZRisF60AiFMD
c32yk2qVxb7e+l6/uQxNj7m1P3YE2BrWQDa26wIDAQABAoIBAEahytv6ABqCqUSV
TE94hmHfzcCZezwWhWs00KveX3t6tQD+f/0osnAXZERJEiNl9FOphdbLLKNP4jSO
CzUFtDyIfsK+mgxhXJpTACCcYyOYEdpGqq9iKeNuPyLCXxQnmSjBH0uBCnAIefZu
S1SQr8CV6B1yIe+3sxt4u4TvupWLnJFsRicDYw0ibR/z7ps6pQJTg6peQk4Ng+Um
rXs8FShWBw8pTctVCqCBWmlGqzOdqafIYu2FO3luznv7fLVJMTgXodUUgdLNVZIM
2eu/c2O1ADI1REGDJU+0Arg8DMollKORGz+QDGJ6QOJIuQ4vq5dRtsPZVeu1m/tD
xzbC+hkCgYEA8Dlj1BrXarklQlb4Wil+v86fzbca3n+7zS4Apc9F3dBT7Y45ZGHO
jYCRTN1+R6kdxAM2rElA7/UzPvJhWBuOQ8hjowMaKNBKfCRkIRm4ChE6RP6iM1Op
oMpiSxx0yqIk4wAvRnADQi/qHCltSCLrDT6Zuob9EqOl/KZdxuuzqn0CgYEAxute
DtfMxbiyM0xocRVAdaEUJWJ+Rd2xdZYD3epbM9OGZs1/Nnf73a5JbRzPmqe8nndb
9tKaR/01x/YlMVcQWHMI2dWcROiGwFAQSHcP54BrZPv4LRCmOeSiskxzpB4qEze0
l7BlTvJyuJiTVTghMBFobQzNloJ21Y0MQ2dxO4cCgYBwKdu6xW2fnyMOfp0nPAi6
djeXTc915B5EBx62TLlKgGMvoCCcBi7zUvyE70ZvHz+OrhFxECMJ52suEO3yvasH
ayFak7A7LkYZAMTfz6pmyPR0EpCZdo7VTKnoeDjwBBVFCGkKcnKTDNw6mf00mVk2
rewJc83mThLKjMNshdE14QKBgA8f4EPyppA2Dd6Wpa5Ldl47RCPfjEhVpeOR53Nd
GVgkciio4U5L6yucz9prAWH59P57htOKic6FcyxkC8nnm8eN35NoiXw3zd8bd1F7
NAtfGUtRWTpb9LecKb6yz2wgGwThDGsoL1vEVXKxryognW1hNXZtLciO3Og51D/f
wp1LAoGBAOVAQcs2ojmVBxAa1B6uXFUMAlVuBHKc9X9SDWqbjNlOB+VI2h/G4mxE
9ZPPIh06rVIZGtVpm0ObtHmwa0ByD7WbY/RIeubs3V4bNoWmtbVqill+Hadd+qu4
WU2pqiheN1BVIW68LFdYz3D5Ncy+pS6YUuyV7OfE8jSYiXla1V1j
-----END RSA PRIVATE KEY-----';

$rsaPublicKey = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqlAJ7DC8drlmKbpVAxS
+vmAw02d7VVgXMPOKunElE1YSh0u1PhzIVTJVh4wVk0cJZhE9fyg+1mGwCejSjNm
n5SXncfKBVdaX+WEDt7UYpjbcyiMX2SsNDxapXOwKtjw5q47Z61lEBpdaW5xerBh
yuUdprqyAholdsOxZbRo+jevaXnWgvZhsNZmIGvQeF9aEoXLn6bg6u692om6odnO
4rN/nRRqyx655soTGkkj8Sr1XovaGTR4m1Fq3RumPx37Cp14Mr4zaRgt/GxcMXER
E4ug3amBJ53qN91NZRisF60AiFMDc32yk2qVxb7e+l6/uQxNj7m1P3YE2BrWQDa2
6wIDAQAB
-----END PUBLIC KEY-----';

$rsaToken = Token::create()
    ->withPayload(['user_id' => 456, 'role' => 'admin'])
    ->withExpiration(7200) // 2小时
    ->sign($rsaPrivateKey, 'RS256');

echo 'RSA Token: ' . $rsaToken . "\n";

try {
    $rsaParser = Token::parse($rsaToken)->verify($rsaPublicKey, 'RS256');
    echo 'RSA Token is valid! User ID: ' . $rsaParser->getClaim('user_id') . "\n";
} catch (Exception $e) {
    echo 'RSA Token validation failed: ' . $e->getMessage() . "\n";
}

// 4. 快速方法
echo "\n--- Quick Methods ---\n";

// 快速创建token
$quickToken = Token::make(['user_id' => 789], $secret, 'HS256', 1800); // 30分钟
echo 'Quick Token: ' . $quickToken . "\n";

// 快速验证和获取数据
try {
    $claims = Token::check($quickToken, $secret, 'HS256');
    echo 'Quick validation successful! Claims: ' . json_encode($claims) . "\n";
} catch (Exception $e) {
    echo 'Quick validation failed: ' . $e->getMessage() . "\n";
}
