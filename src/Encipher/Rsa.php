<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Encipher;

use Vinchan\Token\Contracts\EncipherInterface;

class Rsa implements EncipherInterface
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
        if (! $this->publicKey) {
            throw new \RuntimeException('Public key not set');
        }

        $encrypted = '';
        $success = openssl_public_encrypt($string, $encrypted, $this->publicKey);

        if (! $success) {
            throw new \RuntimeException('RSA encryption failed');
        }

        return base64_encode($encrypted);
    }

    public function decode(string $string): bool|string
    {
        if (! $this->privateKey) {
            throw new \RuntimeException('Private key not set');
        }

        $encryptedData = base64_decode($string);
        if ($encryptedData === false) {
            return false;
        }

        $decrypted = '';
        $success = openssl_private_decrypt($encryptedData, $decrypted, $this->privateKey);

        if (! $success) {
            return false;
        }

        return $decrypted;
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
}
