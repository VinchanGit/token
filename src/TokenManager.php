<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token;

use Vinchan\Token\Exception\ExpiredException;
use Vinchan\Token\Exception\InvalidTokenException;
use Vinchan\Token\Exception\SignatureException;
use Vinchan\Token\Signer\SignerFactory;

/**
 * Token 管理器 - 专业的JWT token管理.
 */
class TokenManager
{
    private ?Authenticatable $authenticatable = null;

    private string $algorithm = 'HS256';

    private ?int $ttl = null;

    private ?string $issuer = null;

    private ?string $audience = null;

    private string $configKey = 'default';

    /**
     * 使用 Authenticatable 值对象设置载荷.
     */
    public function payload(Authenticatable $authenticatable): self
    {
        $this->authenticatable = $authenticatable;
        return $this;
    }

    /**
     * 设置签名算法.
     */
    public function algorithm(string $algorithm): self
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * 设置 TTL（生存时间）秒数.
     */
    public function ttl(int $seconds): self
    {
        $this->ttl = $seconds;
        return $this;
    }

    /**
     * 设置签发者声明.
     */
    public function issuer(string $issuer): self
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * 设置受众声明.
     */
    public function audience(string $audience): self
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * 设置要使用的配置键.
     */
    public function config(string $key): self
    {
        $this->configKey = $key;
        return $this;
    }

    /**
     * 生成 JWT token.
     */
    public function generate(?string $key = null): string
    {
        if ($this->authenticatable === null) {
            throw new SignatureException('载荷是必需的');
        }

        $config = $this->getConfig();
        $secretKey = $key ?? $config['secret_key'] ?? 'your-secret-key';
        $algorithm = $this->algorithm ?? $config['algorithm'] ?? 'HS256';

        // 构建载荷
        $payload = $this->authenticatable->toArray();

        // 添加标准声明
        $ttl = $this->ttl ?? $config['ttl'] ?? 3600;
        $payload['exp'] = time() + $ttl;

        if ($this->issuer !== null || isset($config['issuer'])) {
            $payload['iss'] = $this->issuer ?? $config['issuer'];
        }

        if ($this->audience !== null || isset($config['audience'])) {
            $payload['aud'] = $this->audience ?? $config['audience'];
        }

        // 构建头部
        $header = ['typ' => 'JWT', 'alg' => $algorithm];

        // 创建签名器
        $signer = SignerFactory::create($algorithm);

        // 验证密钥
        if (! $signer->isValidKey($secretKey)) {
            throw new SignatureException("算法 {$algorithm} 的密钥无效");
        }

        // 编码头部和载荷
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));

        // 创建签名输入
        $signingInput = $headerEncoded . '.' . $payloadEncoded;

        // 生成签名
        $signature = $signer->sign($signingInput, $secretKey);

        return $signingInput . '.' . $signature;
    }

    /**
     * 验证 token 是否有效.
     */
    public function verify(string $token, ?string $key = null): bool
    {
        try {
            $config = $this->getConfig();
            $secretKey = $key ?? $config['secret_key'] ?? 'your-secret-key';
            $this->parseAndVerifyToken($token, $secretKey);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * 从 token 获取 Authenticatable 信息.
     */
    public function info(string $token, ?string $key = null): ?Authenticatable
    {
        try {
            $config = $this->getConfig();
            $secretKey = $key ?? $config['secret_key'] ?? 'your-secret-key';
            $payload = $this->parseAndVerifyToken($token, $secretKey);

            // 确保声明中存在 ID
            if (! isset($payload['id'])) {
                return null;
            }

            return Authenticatable::fromArray($payload);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * 流畅 API 的静态工厂方法.
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * 使用指定配置键创建 Token 管理器实例.
     */
    public static function with(string $configKey): self
    {
        return (new self())->config($configKey);
    }

    /**
     * 解析并验证 token，返回载荷数组.
     */
    private function parseAndVerifyToken(string $token, string $key): array
    {
        // 基础验证
        if (empty($token) || substr_count($token, '.') !== 2) {
            throw new InvalidTokenException('无效的 token 格式');
        }

        $parts = explode('.', $token);
        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        // 解码头部
        $headerJson = $this->base64UrlDecode($headerEncoded);
        $header = json_decode($headerJson, true);

        if ($header === null) {
            throw new InvalidTokenException('无效的头部 JSON');
        }

        // 检查算法
        $algorithm = $header['alg'] ?? null;
        if ($algorithm !== $this->algorithm) {
            throw new InvalidTokenException("算法不匹配：期望 {$this->algorithm}，得到 {$algorithm}");
        }

        // 解码载荷
        $payloadJson = $this->base64UrlDecode($payloadEncoded);
        $payload = json_decode($payloadJson, true);

        if ($payload === null) {
            throw new InvalidTokenException('无效的载荷 JSON');
        }

        // 创建签名器并验证签名
        $signer = SignerFactory::create($algorithm);
        $signingInput = $headerEncoded . '.' . $payloadEncoded;

        if (! $signer->verify($signingInput, $signatureEncoded, $key)) {
            throw new SignatureException('签名验证失败');
        }

        // 检查过期时间
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new ExpiredException('Token 已过期');
        }

        // 检查生效时间
        if (isset($payload['nbf']) && $payload['nbf'] > time()) {
            throw new ExpiredException('Token 尚未生效');
        }

        return $payload;
    }

    /**
     * 获取配置数组.
     */
    private function getConfig(): array
    {
        static $configs = [];

        if (! isset($configs[$this->configKey])) {
            // 尝试使用 function_exists 加载配置以避免在非 Hyperf 环境中出错
            if (function_exists('config')) {
                $configs[$this->configKey] = config("token.{$this->configKey}", []);
            } else {
                // 测试环境的后备方案
                $configs[$this->configKey] = [];
            }
        }

        return $configs[$this->configKey];
    }

    /**
     * Base64 URL 安全编码
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL 安全解码
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;

        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new InvalidTokenException('无效的 base64url 编码');
        }

        return $decoded;
    }
}
