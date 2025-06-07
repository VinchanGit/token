<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Signer;

use Vinchan\Token\Exception\SignatureException;

/**
 * HMAC 签名器
 * 支持 HS256、HS384、HS512 算法.
 */
class HmacSigner extends AbstractSigner
{
    /**
     * 支持的算法映射到哈希算法.
     */
    private const ALGORITHM_MAP = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    private string $algorithm;

    private string $hashAlgorithm;

    /**
     * 创建新的 HMAC 签名器.
     */
    public function __construct(string $algorithm = 'HS256')
    {
        $this->algorithm = $algorithm;
        $this->hashAlgorithm = $this->getHashAlgorithmFromJwt($algorithm);
        $this->supportedAlgorithms = array_keys(self::ALGORITHM_MAP);
    }

    /**
     * 获取签名算法名称.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * 使用提供的密钥对给定数据进行签名.
     */
    public function sign(string $data, string $key): string
    {
        if (! $this->isValidKey($key)) {
            throw SignatureException::invalidKey('HMAC 密钥不能为空');
        }

        $signature = hash_hmac($this->getHashAlgorithm(), $data, $key, true);

        return $this->base64UrlEncode($signature);
    }

    /**
     * 验证给定数据的签名.
     */
    public function verify(string $data, string $signature, string $key): bool
    {
        if (! $this->isValidKey($key)) {
            return false;
        }

        $expectedSignature = $this->sign($data, $key);

        return $this->constantTimeEquals($expectedSignature, $signature);
    }

    /**
     * 检查提供的密钥对此签名器是否有效.
     */
    public function isValidKey(string $key): bool
    {
        return ! empty($key);
    }

    /**
     * 创建 HS256 签名器.
     */
    public static function hs256(): self
    {
        return new self('HS256');
    }

    /**
     * 创建 HS384 签名器.
     */
    public static function hs384(): self
    {
        return new self('HS384');
    }

    /**
     * 创建 HS512 签名器.
     */
    public static function hs512(): self
    {
        return new self('HS512');
    }

    /**
     * 获取此签名器的哈希算法.
     */
    protected function getHashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    /**
     * 从 JWT 算法名称获取哈希算法.
     */
    private function getHashAlgorithmFromJwt(string $algorithm): string
    {
        $algorithms = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];

        if (! isset($algorithms[$algorithm])) {
            throw SignatureException::invalidKey("不支持的 HMAC 算法: {$algorithm}");
        }

        return $algorithms[$algorithm];
    }
}
