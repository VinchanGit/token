<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Encipher;

use Vinchan\Token\Contracts\EncipherInterface;

class Hmac implements EncipherInterface
{
    private string $algorithm;

    private string $secret;

    public function __construct(string $algorithm = 'sha256', string $secret = '')
    {
        $this->algorithm = $this->validateAlgorithm($algorithm);
        $this->secret = $secret;
    }

    public function encode(string $string): string
    {
        if (empty($this->secret)) {
            throw new \RuntimeException('Secret key not set');
        }

        // 生成随机 IV
        $iv = random_bytes(16);

        // 使用 AES-256-CBC 加密
        $encrypted = openssl_encrypt($string, 'aes-256-cbc', $this->secret, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // 组合 IV 和加密数据
        $data = $iv . $encrypted;

        // 生成 HMAC 用于完整性验证
        $hmac = hash_hmac($this->algorithm, $data, $this->secret, true);

        // 组合 HMAC 和数据
        $result = $hmac . $data;

        return base64_encode($result);
    }

    public function decode(string $string): bool|string
    {
        if (empty($this->secret)) {
            throw new \RuntimeException('Secret key not set');
        }

        $data = base64_decode($string);
        if ($data === false) {
            return false;
        }

        // 获取哈希长度
        $hashLength = $this->getHashLength();

        if (strlen($data) < $hashLength + 16) {
            return false;
        }

        // 分离 HMAC 和数据
        $hmac = substr($data, 0, $hashLength);
        $encryptedData = substr($data, $hashLength);

        // 验证 HMAC
        $expectedHmac = hash_hmac($this->algorithm, $encryptedData, $this->secret, true);
        if (! hash_equals($hmac, $expectedHmac)) {
            return false;
        }

        // 分离 IV 和加密数据
        $iv = substr($encryptedData, 0, 16);
        $encrypted = substr($encryptedData, 16);

        // 解密
        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $this->secret, OPENSSL_RAW_DATA, $iv);

        return $decrypted;
    }

    public function verify(string $data, string $signature): bool
    {
        if (empty($this->secret)) {
            throw new \RuntimeException('Secret key not set');
        }

        $expectedSignature = $this->encode($data);

        // 使用恒定时间比较防止时序攻击
        return hash_equals($expectedSignature, $signature);
    }

    public function setSecret(string $secret): self
    {
        $this->secret = $secret;
        return $this;
    }

    public function setAlgorithm(string $algorithm): self
    {
        $this->algorithm = $this->validateAlgorithm($algorithm);
        return $this;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    private function validateAlgorithm(string $algorithm): string
    {
        $supported = ['sha256', 'sha384', 'sha512'];
        if (! in_array($algorithm, $supported)) {
            throw new \InvalidArgumentException("Unsupported algorithm: {$algorithm}. Supported algorithms: " . implode(', ', $supported));
        }
        return $algorithm;
    }

    private function getHashLength(): int
    {
        return match ($this->algorithm) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => 32,
        };
    }
}
