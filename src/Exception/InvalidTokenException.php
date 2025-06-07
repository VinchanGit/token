<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Exception;

/**
 * Exception thrown when token is invalid.
 */
class InvalidTokenException extends TokenException
{
    /**
     * Create exception for invalid token.
     */
    public static function invalid(string $message = 'Invalid token'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for invalid token structure.
     */
    public static function invalidStructure(string $message = 'Invalid token structure'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for invalid header.
     */
    public static function invalidHeader(string $message = 'Invalid token header'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for invalid payload.
     */
    public static function invalidPayload(string $message = 'Invalid token payload'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for invalid signature.
     */
    public static function invalidSignature(string $message = 'Invalid token signature'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for missing required claim.
     */
    public static function missingClaim(string $claim, string $message = ''): self
    {
        $message = $message ?: "Required claim '{$claim}' is missing";

        return new static($message, 400);
    }

    /**
     * Create exception for invalid claim value.
     */
    public static function invalidClaim(string $claim, string $message = ''): self
    {
        $message = $message ?: "Invalid value for claim '{$claim}'";

        return new static($message, 400);
    }
}
