<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token\Utils;

use Vinchan\Token\Utils\KeyGenerator;
use VinchanTest\Token\TestCase;

/**
 * @internal
 * @coversNothing
 */
class KeyGeneratorTest extends TestCase
{
    public function testGenerateHmacSecret(): void
    {
        $key = KeyGenerator::generateHmacSecret();

        self::assertIsString($key);
        self::assertNotEmpty($key);
        self::assertGreaterThanOrEqual(64, strlen($key)); // 32 bytes hex encoded
    }

    public function testGenerateRsaKeyPair(): void
    {
        $keyPair = KeyGenerator::generateRsaKeyPair();

        self::assertIsArray($keyPair);
        self::assertArrayHasKey('private', $keyPair);
        self::assertArrayHasKey('public', $keyPair);

        $privateKey = $keyPair['private'];
        $publicKey = $keyPair['public'];

        self::assertIsString($privateKey);
        self::assertIsString($publicKey);
        self::assertStringContainsString('-----BEGIN PRIVATE KEY-----', $privateKey);
        self::assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
    }

    public function testGenerateEcdsaKeyPair(): void
    {
        $keyPair = KeyGenerator::generateEcdsaKeyPair();

        self::assertIsArray($keyPair);
        self::assertArrayHasKey('private', $keyPair);
        self::assertArrayHasKey('public', $keyPair);

        $privateKey = $keyPair['private'];
        $publicKey = $keyPair['public'];

        self::assertIsString($privateKey);
        self::assertIsString($publicKey);
        self::assertStringContainsString('-----BEGIN PRIVATE KEY-----', $privateKey);
        self::assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
    }

    public function testGenerateForAlgorithm(): void
    {
        // HMAC algorithms
        $hmacSecret = KeyGenerator::generateForAlgorithm('HS256');
        self::assertIsString($hmacSecret);

        // RSA algorithms
        $rsaKeys = KeyGenerator::generateForAlgorithm('RS256');
        self::assertIsArray($rsaKeys);
        self::assertArrayHasKey('private', $rsaKeys);
        self::assertArrayHasKey('public', $rsaKeys);

        // ECDSA algorithms
        $ecdsaKeys = KeyGenerator::generateForAlgorithm('ES256');
        self::assertIsArray($ecdsaKeys);
        self::assertArrayHasKey('private', $ecdsaKeys);
        self::assertArrayHasKey('public', $ecdsaKeys);
    }

    public function testGenerateForUnsupportedAlgorithm(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        KeyGenerator::generateForAlgorithm('INVALID');
    }
}
