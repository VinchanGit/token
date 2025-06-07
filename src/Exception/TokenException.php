<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Exception;

use Exception;

/**
 * Token 异常基类
 * 所有 Token 相关异常的父类.
 */
class TokenException extends \Exception
{
    /**
     * 创建新的 Token 异常.
     */
    public function __construct(string $message = '', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    /**
     * 创建带有自定义消息的异常.
     */
    public static function withMessage(string $message): self
    {
        return new self($message);
    }

    /**
     * 创建带有代码和消息的异常.
     */
    public static function withCode(string $message, int $code): self
    {
        return new self($message, $code);
    }

    /**
     * Create exception for invalid token format.
     */
    public static function invalidFormat(string $message = 'Invalid token format'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for malformed token.
     */
    public static function malformed(string $message = 'Malformed token'): self
    {
        return new static($message, 400);
    }

    /**
     * Create exception for empty token.
     */
    public static function empty(string $message = 'Empty token provided'): self
    {
        return new static($message, 400);
    }
}
