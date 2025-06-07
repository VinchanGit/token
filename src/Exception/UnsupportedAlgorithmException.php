<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Exception;

/**
 * Exception thrown when algorithm is not supported.
 */
class UnsupportedAlgorithmException extends TokenException
{
    /**
     * Create exception for unsupported algorithm.
     */
    public static function unsupported(string $algorithm, string $message = ''): self
    {
        $message = $message ?: "Unsupported algorithm: {$algorithm}";

        return new static($message, 400);
    }

    /**
     * Create exception for algorithm not found.
     */
    public static function notFound(string $algorithm, string $message = ''): self
    {
        $message = $message ?: "Algorithm not found: {$algorithm}";

        return new static($message, 400);
    }

    /**
     * Create exception for missing algorithm.
     */
    public static function missing(string $message = 'Algorithm is required'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception with list of supported algorithms.
     */
    public static function withSupportedList(string $algorithm, array $supported, string $message = ''): self
    {
        $supportedList = implode(', ', $supported);
        $message = $message ?: "Unsupported algorithm '{$algorithm}'. Supported algorithms: {$supportedList}";

        return new static($message, 400);
    }
}
