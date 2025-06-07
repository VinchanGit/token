<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Signer;

use Vinchan\Token\Exception\SignatureException;

/**
 * ECDSA signer for ES256, ES384, ES512 algorithms.
 */
class EcdsaSigner extends AbstractSigner
{
    private string $algorithm;

    private int $signatureType;

    private int $signatureLength;

    /**
     * Create a new ECDSA signer.
     */
    public function __construct(string $algorithm = 'ES256')
    {
        $this->algorithm = $algorithm;
        $this->signatureType = $this->getSignatureTypeFromJwt($algorithm);
        $this->signatureLength = $this->getSignatureLengthFromJwt($algorithm);
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
            throw SignatureException::invalidKey('Invalid ECDSA private key');
        }

        $privateKey = $this->loadPrivateKey($key);

        if (! openssl_sign($data, $signature, $privateKey, $this->signatureType)) {
            throw SignatureException::verificationFailed('Failed to sign data with ECDSA private key');
        }

        // Convert DER signature to IEEE P1363 format
        $signature = $this->derToIeee($signature);

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

            // Convert IEEE P1363 signature to DER format
            $signature = $this->ieeeToDer($signature);

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
                $details = openssl_pkey_get_details($resource);

                return $details['type'] === \OPENSSL_KEYTYPE_EC;
            }

            // Try to load as public key
            $resource = openssl_pkey_get_public($key);

            if ($resource !== false) {
                $details = openssl_pkey_get_details($resource);

                return $details['type'] === \OPENSSL_KEYTYPE_EC;
            }

            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Create ES256 signer.
     */
    public static function es256(): self
    {
        return new self('ES256');
    }

    /**
     * Create ES384 signer.
     */
    public static function es384(): self
    {
        return new self('ES384');
    }

    /**
     * Create ES512 signer.
     */
    public static function es512(): self
    {
        return new self('ES512');
    }

    /**
     * Get the hash algorithm for this signer.
     */
    protected function getHashAlgorithm(): string
    {
        $algorithms = [
            'ES256' => 'sha256',
            'ES384' => 'sha384',
            'ES512' => 'sha512',
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
            throw SignatureException::invalidKey('Invalid ECDSA private key format');
        }

        $details = openssl_pkey_get_details($privateKey);

        if ($details['type'] !== \OPENSSL_KEYTYPE_EC) {
            throw SignatureException::keyFormatMismatch($this->algorithm, 'Key is not an ECDSA key');
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
            throw SignatureException::invalidKey('Invalid ECDSA public key format');
        }

        $details = openssl_pkey_get_details($publicKey);

        if ($details['type'] !== \OPENSSL_KEYTYPE_EC) {
            throw SignatureException::keyFormatMismatch($this->algorithm, 'Key is not an ECDSA key');
        }

        return $publicKey;
    }

    /**
     * Get OpenSSL signature type from JWT algorithm name.
     */
    private function getSignatureTypeFromJwt(string $algorithm): int
    {
        $algorithms = [
            'ES256' => \OPENSSL_ALGO_SHA256,
            'ES384' => \OPENSSL_ALGO_SHA384,
            'ES512' => \OPENSSL_ALGO_SHA512,
        ];

        if (! isset($algorithms[$algorithm])) {
            throw SignatureException::invalidKey("Unsupported ECDSA algorithm: {$algorithm}");
        }

        return $algorithms[$algorithm];
    }

    /**
     * Get signature length from JWT algorithm name.
     */
    private function getSignatureLengthFromJwt(string $algorithm): int
    {
        $lengths = [
            'ES256' => 64,
            'ES384' => 96,
            'ES512' => 132,
        ];

        return $lengths[$algorithm];
    }

    /**
     * Convert DER signature to IEEE P1363 format.
     */
    private function derToIeee(string $signature): string
    {
        $offset = 0;
        $r = $this->readDerInteger($signature, $offset);
        $s = $this->readDerInteger($signature, $offset);

        $rLength = \strlen($r);
        $sLength = \strlen($s);
        $expectedLength = $this->signatureLength / 2;

        // Pad with zeros if necessary
        $r = str_pad($r, $expectedLength, "\x00", \STR_PAD_LEFT);
        $s = str_pad($s, $expectedLength, "\x00", \STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Convert IEEE P1363 signature to DER format.
     */
    private function ieeeToDer(string $signature): string
    {
        if (\strlen($signature) !== $this->signatureLength) {
            throw SignatureException::invalid('Invalid signature length');
        }

        $rLength = $this->signatureLength / 2;
        $r = substr($signature, 0, $rLength);
        $s = substr($signature, $rLength);

        // Remove leading zeros
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Ensure positive integers
        if (\ord($r[0] ?? '') & 0x80) {
            $r = "\x00" . $r;
        }

        if (\ord($s[0] ?? '') & 0x80) {
            $s = "\x00" . $s;
        }

        return $this->encodeDerSequence([
            $this->encodeDerInteger($r),
            $this->encodeDerInteger($s),
        ]);
    }

    /**
     * Read DER integer from signature.
     */
    private function readDerInteger(string $data, int &$offset): string
    {
        if ($data[$offset] !== "\x02") {
            throw SignatureException::invalid('Invalid DER integer tag');
        }
        ++$offset;

        $length = \ord($data[$offset]);
        ++$offset;

        $integer = substr($data, $offset, $length);
        $offset += $length;

        // Remove leading zero if present
        if ($length > 1 && $integer[0] === "\x00") {
            $integer = substr($integer, 1);
        }

        return $integer;
    }

    /**
     * Encode DER integer.
     */
    private function encodeDerInteger(string $integer): string
    {
        return "\x02" . \chr(\strlen($integer)) . $integer;
    }

    /**
     * Encode DER sequence.
     */
    private function encodeDerSequence(array $elements): string
    {
        $content = implode('', $elements);

        return "\x30" . \chr(\strlen($content)) . $content;
    }
}
