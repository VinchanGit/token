<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Utils;

/**
 * JWT 密钥生成工具类.
 */
class KeyGenerator
{
    /**
     * 生成随机 HMAC 密钥.
     */
    public static function generateHmacSecret(int $length = 32): string
    {
        if ($length < 16) {
            throw new \InvalidArgumentException('HMAC 密钥长度必须至少为 16 字节');
        }

        return bin2hex(random_bytes($length));
    }

    /**
     * 生成 RSA 密钥对.
     */
    public static function generateRsaKeyPair(int $bits = 2048): array
    {
        if ($bits < 2048) {
            throw new \InvalidArgumentException('RSA 密钥大小必须至少为 2048 位');
        }

        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => $bits,
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
        ];

        $resource = openssl_pkey_new($config);

        if ($resource === false) {
            throw new \RuntimeException('生成 RSA 密钥对失败');
        }

        // 导出私钥
        if (! openssl_pkey_export($resource, $privateKey)) {
            throw new \RuntimeException('导出 RSA 私钥失败');
        }

        // 导出公钥
        $details = openssl_pkey_get_details($resource);

        if ($details === false) {
            throw new \RuntimeException('获取 RSA 密钥详情失败');
        }

        return [
            'private' => $privateKey,
            'public' => $details['key'],
        ];
    }

    /**
     * 生成 ECDSA 密钥对.
     */
    public static function generateEcdsaKeyPair(string $curve = 'prime256v1'): array
    {
        $supportedCurves = [
            'prime256v1', // P-256 用于 ES256
            'secp384r1',  // P-384 用于 ES384
            'secp521r1',  // P-521 用于 ES512
        ];

        if (! \in_array($curve, $supportedCurves, true)) {
            throw new \InvalidArgumentException(
                "不支持的曲线: {$curve}。支持的曲线: " . implode(', ', $supportedCurves),
            );
        }

        $config = [
            'digest_alg' => 'sha256',
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ];

        $resource = openssl_pkey_new($config);

        if ($resource === false) {
            throw new \RuntimeException('生成 ECDSA 密钥对失败');
        }

        // 导出私钥
        if (! openssl_pkey_export($resource, $privateKey)) {
            throw new \RuntimeException('导出 ECDSA 私钥失败');
        }

        // 导出公钥
        $details = openssl_pkey_get_details($resource);

        if ($details === false) {
            throw new \RuntimeException('获取 ECDSA 密钥详情失败');
        }

        return [
            'private' => $privateKey,
            'public' => $details['key'],
        ];
    }

    /**
     * 获取 ECDSA 算法推荐的曲线
     */
    public static function getRecommendedCurve(string $algorithm): string
    {
        $curves = [
            'ES256' => 'prime256v1',
            'ES384' => 'secp384r1',
            'ES512' => 'secp521r1',
        ];

        if (! isset($curves[$algorithm])) {
            throw new \InvalidArgumentException("不支持的 ECDSA 算法: {$algorithm}");
        }

        return $curves[$algorithm];
    }

    /**
     * 获取 RSA 算法推荐的密钥大小.
     */
    public static function getRecommendedKeySize(string $algorithm): int
    {
        $sizes = [
            'RS256' => 2048,
            'RS384' => 2048,
            'RS512' => 2048,
        ];

        if (! isset($sizes[$algorithm])) {
            throw new \InvalidArgumentException("不支持的 RSA 算法: {$algorithm}");
        }

        return $sizes[$algorithm];
    }

    /**
     * 为特定算法生成密钥.
     */
    public static function generateForAlgorithm(string $algorithm): array|string
    {
        if (str_starts_with($algorithm, 'HS')) {
            return self::generateHmacSecret();
        }

        if (str_starts_with($algorithm, 'RS')) {
            $keySize = self::getRecommendedKeySize($algorithm);

            return self::generateRsaKeyPair($keySize);
        }

        if (str_starts_with($algorithm, 'ES')) {
            $curve = self::getRecommendedCurve($algorithm);

            return self::generateEcdsaKeyPair($curve);
        }

        throw new \InvalidArgumentException("不支持的算法: {$algorithm}");
    }
}
