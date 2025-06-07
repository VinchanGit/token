<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token\Exception;

use PHPUnit\Framework\TestCase;
use Vinchan\Token\Exception\ExpiredException;
use Vinchan\Token\Exception\InvalidTokenException;
use Vinchan\Token\Exception\SignatureException;
use Vinchan\Token\Exception\TokenException;
use Vinchan\Token\Exception\UnsupportedAlgorithmException;

/**
 * @internal
 * @coversNothing
 */
class ExceptionTest extends TestCase
{
    public function testTokenException(): void
    {
        $exception = new TokenException('Test message');

        self::assertInstanceOf(\Exception::class, $exception);
        self::assertEquals('Test message', $exception->getMessage());
    }

    public function testSignatureException(): void
    {
        $exception = SignatureException::verificationFailed();

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertStringContainsString('verification failed', $exception->getMessage());
    }

    public function testSignatureExceptionInvalidKey(): void
    {
        $exception = SignatureException::invalidKey('Invalid key format');

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertEquals('Invalid key format', $exception->getMessage());
    }

    public function testSignatureExceptionMissingKey(): void
    {
        $exception = SignatureException::missingKey('Key is required');

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertEquals('Key is required', $exception->getMessage());
    }

    public function testExpiredException(): void
    {
        $timestamp = time();
        $exception = ExpiredException::expiredAt($timestamp);

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertStringContainsString('expired', $exception->getMessage());
    }

    public function testExpiredExceptionNotValidBefore(): void
    {
        $timestamp = time() + 3600;
        $exception = ExpiredException::notValidBefore($timestamp);

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertStringContainsString('not valid before', $exception->getMessage());
    }

    public function testInvalidTokenException(): void
    {
        $exception = InvalidTokenException::invalidFormat('Invalid token format');

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertEquals('Invalid token format', $exception->getMessage());
    }

    public function testInvalidTokenExceptionInvalidHeader(): void
    {
        $exception = InvalidTokenException::invalidHeader('Invalid header');

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertEquals('Invalid header', $exception->getMessage());
    }

    public function testInvalidTokenExceptionInvalidPayload(): void
    {
        $exception = InvalidTokenException::invalidPayload('Invalid payload');

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertEquals('Invalid payload', $exception->getMessage());
    }

    public function testUnsupportedAlgorithmException(): void
    {
        $supportedAlgorithms = ['HS256', 'HS384', 'HS512'];
        $exception = UnsupportedAlgorithmException::withSupportedList('INVALID', $supportedAlgorithms);

        self::assertInstanceOf(TokenException::class, $exception);
        self::assertStringContainsString('INVALID', $exception->getMessage());
        self::assertStringContainsString('HS256', $exception->getMessage());
    }
}
