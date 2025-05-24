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

        // 生成随机密钥用于对称加密
        $symmetricKey = random_bytes(32);

        // 生成随机 IV
        $iv = random_bytes(16);

        // 使用 AES-256-CBC 加密原始数据
        $encrypted = openssl_encrypt($string, 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // 对对称密钥进行签名
        $keySignature = '';
        $success = openssl_sign($symmetricKey, $keySignature, $this->privateKey, $this->getOpenSSLAlgorithm());

        if (! $success) {
            throw new \RuntimeException('Key signing failed');
        }

        // 组合签名长度、签名、对称密钥、IV和加密数据
        $signatureLength = pack('N', strlen($keySignature));
        $keyLength = pack('N', strlen($symmetricKey));
        $result = $signatureLength . $keySignature . $keyLength . $symmetricKey . $iv . $encrypted;

        return base64_encode($result);
    }

    public function decode(string $string): bool|string
    {
        if (! $this->publicKey) {
            throw new \RuntimeException('Public key not set');
        }

        $data = base64_decode($string);
        if ($data === false) {
            return false;
        }

        if (strlen($data) < 8) {
            return false;
        }

        $offset = 0;

        // 解析签名长度和签名
        $signatureLength = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        if (strlen($data) < $offset + $signatureLength + 4) {
            return false;
        }

        $keySignature = substr($data, $offset, $signatureLength);
        $offset += $signatureLength;

        // 解析对称密钥长度和密钥
        $keyLength = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        if (strlen($data) < $offset + $keyLength + 16) {
            return false;
        }

        $symmetricKey = substr($data, $offset, $keyLength);
        $offset += $keyLength;

        // 验证对称密钥的签名
        $verifyResult = openssl_verify($symmetricKey, $keySignature, $this->publicKey, $this->getOpenSSLAlgorithm());
        if ($verifyResult !== 1) {
            return false;
        }

        // 提取 IV 和加密数据
        $iv = substr($data, $offset, 16);
        $encrypted = substr($data, $offset + 16);

        // 解密
        return openssl_decrypt($encrypted, 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, $iv);
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
