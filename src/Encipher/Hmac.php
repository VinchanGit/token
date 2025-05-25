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

        // 使用 HMAC 对 JWT payload 进行签名
        $signature = hash_hmac($this->algorithm, $string, $this->secret, true);

        return base64_encode($signature);
    }

    public function decode(string $string): bool|string
    {
        // 对于 HMAC，decode 方法用于验证签名
        // 这里只是解码签名，实际验证需要原始数据
        $decoded = base64_decode($string);
        if ($decoded === false) {
            return false;
        }

        return $decoded;
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

    public function sign(string $headerPayload): string
    {
        return $this->encode($headerPayload);
    }

    public function verifyJwt(string $headerPayload, string $signature): bool
    {
        return $this->verify($headerPayload, $signature);
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
        if (!in_array($algorithm, $supported)) {
            throw new \InvalidArgumentException("Unsupported algorithm: {$algorithm}. Supported algorithms: " . implode(', ', $supported));
        }
        return $algorithm;
    }
}
