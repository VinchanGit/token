<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Signer;

use Vinchan\Token\Exception\SignatureException;

/**
 * RSA signer for RS256, RS384, RS512 algorithms.
 */
class RsaSigner extends AbstractSigner
{
    private string $algorithm;

    private int $signatureType;

    /**
     * Create a new RSA signer.
     */
    public function __construct(string $algorithm = 'RS256')
    {
        $this->algorithm = $algorithm;
        $this->signatureType = $this->getSignatureTypeFromJwt($algorithm);
    }

    /**
     * Get the signature algorithm name.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Sign the given data with the provided key.
     */
    public function sign(string $data, string $key): string
    {
        if (! $this->isValidKey($key)) {
            throw SignatureException::invalidKey('Invalid RSA private key');
        }

        $privateKey = $this->loadPrivateKey($key);

        if (! openssl_sign($data, $signature, $privateKey, $this->signatureType)) {
            throw SignatureException::verificationFailed('Failed to sign data with RSA private key');
        }

        return $this->base64UrlEncode($signature);
    }

    /**
     * Verify the signature of the given data.
     */
    public function verify(string $data, string $signature, string $key): bool
    {
        if (! $this->isValidKey($key)) {
            return false;
        }

        try {
            $publicKey = $this->loadPublicKey($key);
            $signature = $this->base64UrlDecode($signature);

            $result = openssl_verify($data, $signature, $publicKey, $this->signatureType);

            return $result === 1;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if the provided key is valid for this signer.
     */
    public function isValidKey(string $key): bool
    {
        if (empty($key)) {
            return false;
        }

        try {
            // Try to load as private key first
            $resource = openssl_pkey_get_private($key);

            if ($resource !== false) {
                return true;
            }

            // Try to load as public key
            $resource = openssl_pkey_get_public($key);

            return $resource !== false;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Create RS256 signer.
     */
    public static function rs256(): self
    {
        return new self('RS256');
    }

    /**
     * Create RS384 signer.
     */
    public static function rs384(): self
    {
        return new self('RS384');
    }

    /**
     * Create RS512 signer.
     */
    public static function rs512(): self
    {
        return new self('RS512');
    }

    /**
     * Get the hash algorithm for this signer.
     */
    protected function getHashAlgorithm(): string
    {
        $algorithms = [
            'RS256' => 'sha256',
            'RS384' => 'sha384',
            'RS512' => 'sha512',
        ];

        return $algorithms[$this->algorithm];
    }

    /**
     * Load private key resource.
     */
    private function loadPrivateKey(string $key)
    {
        $privateKey = openssl_pkey_get_private($key);

        if ($privateKey === false) {
            throw SignatureException::invalidKey('Invalid RSA private key format');
        }

        return $privateKey;
    }

    /**
     * Load public key resource.
     */
    private function loadPublicKey(string $key)
    {
        // Try to load as public key first
        $publicKey = openssl_pkey_get_public($key);

        if ($publicKey === false) {
            // Try to extract public key from private key
            $privateKey = openssl_pkey_get_private($key);

            if ($privateKey !== false) {
                $details = openssl_pkey_get_details($privateKey);
                $publicKey = openssl_pkey_get_public($details['key']);
            }
        }

        if ($publicKey === false) {
            throw SignatureException::invalidKey('Invalid RSA public key format');
        }

        return $publicKey;
    }

    /**
     * Get OpenSSL signature type from JWT algorithm name.
     */
    private function getSignatureTypeFromJwt(string $algorithm): int
    {
        $algorithms = [
            'RS256' => \OPENSSL_ALGO_SHA256,
            'RS384' => \OPENSSL_ALGO_SHA384,
            'RS512' => \OPENSSL_ALGO_SHA512,
        ];

        if (! isset($algorithms[$algorithm])) {
            throw SignatureException::invalidKey("Unsupported RSA algorithm: {$algorithm}");
        }

        return $algorithms[$algorithm];
    }
}
