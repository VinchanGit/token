<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Encipher;

use Vinchan\Token\Contracts\EncipherInterface;

class Ecdsa implements EncipherInterface
{
    private string $algorithm;

    private false|\OpenSSLAsymmetricKey $privateKey;

    private false|\OpenSSLAsymmetricKey $publicKey;

    public function __construct(string $algorithm = 'sha256', ?string $privateKeyPath = null, ?string $publicKeyPath = null)
    {
        $this->algorithm = $this->validateAlgorithm($algorithm);

        if ($privateKeyPath) {
            $this->privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));
        }

        if ($publicKeyPath) {
            $this->publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));
        }
    }

    public function encode(string $string): string
    {
        if (! $this->privateKey) {
            throw new \RuntimeException('Private key not set');
        }

        // 使用私钥对 JWT payload 进行 ECDSA 签名
        $signature = '';
        $success = openssl_sign($string, $signature, $this->privateKey, $this->getOpenSSLAlgorithm());

        if (! $success) {
            throw new \RuntimeException('ECDSA signing failed');
        }

        return base64_encode($signature);
    }

    public function decode(string $string): bool|string
    {
        // 对于 ECDSA，decode 方法用于解码签名
        // 实际验证需要使用 verify 方法
        $signature = base64_decode($string);
        if ($signature === false) {
            return false;
        }

        return $signature;
    }

    public function verify(string $data, string $signature): bool
    {
        if (! $this->publicKey) {
            throw new \RuntimeException('Public key not set');
        }

        $decodedSignature = base64_decode($signature);
        if ($decodedSignature === false) {
            return false;
        }

        return openssl_verify($data, $decodedSignature, $this->publicKey, $this->getOpenSSLAlgorithm()) === 1;
    }

    public function sign(string $headerPayload): string
    {
        return $this->encode($headerPayload);
    }

    public function verifyJwt(string $headerPayload, string $signature): bool
    {
        return $this->verify($headerPayload, $signature);
    }

    public function setPrivateKey(string $privateKeyPath): self
    {
        $this->privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));
        return $this;
    }

    public function setPublicKey(string $publicKeyPath): self
    {
        $this->publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));
        return $this;
    }

    public function setPrivateKeyFromString(string $privateKey): self
    {
        $this->privateKey = openssl_pkey_get_private($privateKey);
        return $this;
    }

    public function setPublicKeyFromString(string $publicKey): self
    {
        $this->publicKey = openssl_pkey_get_public($publicKey);
        return $this;
    }

    public function generateKeyPair(string $curve = 'prime256v1'): array
    {
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $this->getCurveName($curve),
        ];

        $keyPair = openssl_pkey_new($config);
        if (! $keyPair) {
            throw new \RuntimeException('ECDSA key pair generation failed');
        }

        $privateKey = '';
        openssl_pkey_export($keyPair, $privateKey);

        $publicKeyDetails = openssl_pkey_get_details($keyPair);
        $publicKey = $publicKeyDetails['key'];

        return [
            'private' => $privateKey,
            'public' => $publicKey,
        ];
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

    private function getOpenSSLAlgorithm(): int
    {
        return match ($this->algorithm) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => OPENSSL_ALGO_SHA256,
        };
    }

    private function getCurveName(string $curve): string
    {
        $curves = [
            'prime256v1' => 'prime256v1',  // P-256
            'secp384r1' => 'secp384r1',    // P-384
            'secp521r1' => 'secp521r1',    // P-521
        ];

        return $curves[$curve] ?? 'prime256v1';
    }
}
