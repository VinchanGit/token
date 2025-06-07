<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Exception;

/**
 * 签名异常
 * 当 JWT 签名验证失败或签名相关操作出错时抛出.
 */
class SignatureException extends TokenException
{
    /**
     * Create exception for invalid signature.
     */
    public static function invalid(string $message = 'Invalid token signature'): self
    {
        return new static($message, 401);
    }

    /**
     * Create exception for signature verification failure.
     */
    public static function verificationFailed(string $message = 'Token signature verification failed'): self
    {
        return new static($message, 401);
    }

    /**
     * Create exception for invalid key.
     */
    public static function invalidKey(string $message = 'Invalid signing key provided'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for missing key.
     */
    public static function missingKey(string $message = 'Signing key is required'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for key format mismatch.
     */
    public static function keyFormatMismatch(string $algorithm, string $message = ''): self
    {
        $message = $message ?: "Key format does not match the algorithm: {$algorithm}";

        return new static($message, 400);
    }
}
