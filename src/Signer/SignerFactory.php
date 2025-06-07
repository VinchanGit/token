<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Signer;

use Vinchan\Token\Contract\SignerInterface;
use Vinchan\Token\Exception\UnsupportedAlgorithmException;

/**
 * JWT 签名器工厂类.
 */
class SignerFactory
{
    /** @var array<string, class-string<SignerInterface>> */
    private static array $signers = [
        'HS256' => HmacSigner::class,
        'HS384' => HmacSigner::class,
        'HS512' => HmacSigner::class,
        'RS256' => RsaSigner::class,
        'RS384' => RsaSigner::class,
        'RS512' => RsaSigner::class,
        'ES256' => EcdsaSigner::class,
        'ES384' => EcdsaSigner::class,
        'ES512' => EcdsaSigner::class,
    ];

    /**
     * 为给定算法创建签名器.
     */
    public static function create(string $algorithm): SignerInterface
    {
        if (! isset(self::$signers[$algorithm])) {
            throw UnsupportedAlgorithmException::withSupportedList(
                $algorithm,
                array_keys(self::$signers),
            );
        }

        $signerClass = self::$signers[$algorithm];

        return new $signerClass($algorithm);
    }

    /**
     * 检查算法是否支持
     */
    public static function isSupported(string $algorithm): bool
    {
        return isset(self::$signers[$algorithm]);
    }

    /**
     * 获取所有支持的算法.
     */
    public static function getSupportedAlgorithms(): array
    {
        return array_keys(self::$signers);
    }

    /**
     * 注册自定义签名器.
     */
    public static function register(string $algorithm, string $signerClass): void
    {
        if (! is_subclass_of($signerClass, SignerInterface::class)) {
            throw new \InvalidArgumentException(
                '签名器类必须实现 ' . SignerInterface::class,
            );
        }

        self::$signers[$algorithm] = $signerClass;
    }

    /**
     * 注销签名器.
     */
    public static function unregister(string $algorithm): void
    {
        unset(self::$signers[$algorithm]);
    }

    /**
     * 获取 HMAC 签名器.
     */
    public static function getHmacSigners(): array
    {
        return array_filter(self::$signers, static function ($algorithm) {
            return str_starts_with($algorithm, 'HS');
        }, \ARRAY_FILTER_USE_KEY);
    }

    /**
     * 获取 RSA 签名器.
     */
    public static function getRsaSigners(): array
    {
        return array_filter(self::$signers, static function ($algorithm) {
            return str_starts_with($algorithm, 'RS');
        }, \ARRAY_FILTER_USE_KEY);
    }

    /**
     * 获取 ECDSA 签名器.
     */
    public static function getEcdsaSigners(): array
    {
        return array_filter(self::$signers, static function ($algorithm) {
            return str_starts_with($algorithm, 'ES');
        }, \ARRAY_FILTER_USE_KEY);
    }
}
