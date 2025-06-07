<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Exception;

/**
 * Exception thrown when token is expired.
 */
class ExpiredException extends TokenException
{
    /**
     * Create exception for expired token.
     */
    public static function expired(string $message = 'Token has expired'): self
    {
        return new static($message, 401);
    }

    /**
     * Create exception for token used before valid time.
     */
    public static function beforeValidTime(string $message = 'Token is not yet valid'): self
    {
        return new static($message, 401);
    }

    /**
     * Create exception with timestamp information.
     */
    public static function expiredAt(int $expiredAt, string $message = ''): self
    {
        $message = $message ?: 'Token expired at: ' . date('Y-m-d H:i:s', $expiredAt);

        return new static($message, 401);
    }

    /**
     * Create exception for not before time.
     */
    public static function notValidBefore(int $notBefore, string $message = ''): self
    {
        $message = $message ?: 'Token is not valid before: ' . date('Y-m-d H:i:s', $notBefore);

        return new static($message, 401);
    }
}
