<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Signer;

use Vinchan\Token\Contract\SignerInterface;

/**
 * 抽象签名器基类
 * 提供签名器的通用功能实现.
 */
abstract class AbstractSigner implements SignerInterface
{
    /**
     * 支持的算法列表.
     */
    protected array $supportedAlgorithms = [];

    /**
     * 检查算法是否被支持
     */
    public function supports(string $algorithm): bool
    {
        return in_array($algorithm, $this->supportedAlgorithms, true);
    }

    /**
     * 验证密钥格式（具体实现由子类提供）.
     */
    abstract public function isValidKey(string $key): bool;

    /**
     * 对数据进行签名（具体实现由子类提供）.
     */
    abstract public function sign(string $data, string $key): string;

    /**
     * 验证签名（具体实现由子类提供）.
     */
    abstract public function verify(string $data, string $signature, string $key): bool;

    /**
     * 获取签名算法名称.
     */
    abstract public function getAlgorithm(): string;

    /**
     * Base64 URL 安全编码
     */
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL 安全解码
     */
    protected function base64UrlDecode(string $data): string
    {
        $remainder = \strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($data, '-_', '+/'), true) ?: '';
    }

    /**
     * 安全的字符串比较，防止时序攻击.
     */
    protected function constantTimeEquals(string $left, string $right): bool
    {
        if (\strlen($left) !== \strlen($right)) {
            return false;
        }

        return hash_equals($left, $right);
    }

    /**
     * 获取此签名器使用的哈希算法.
     */
    abstract protected function getHashAlgorithm(): string;
}
