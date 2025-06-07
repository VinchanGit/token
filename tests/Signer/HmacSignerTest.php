<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token\Signer;

use PHPUnit\Framework\TestCase;
use Vinchan\Token\Exception\UnsupportedAlgorithmException;
use Vinchan\Token\Signer\SignerFactory;

/**
 * @internal
 * @coversNothing
 */
class HmacSignerTest extends TestCase
{
    private string $secret;

    protected function setUp(): void
    {
        $this->secret = 'your-256-bit-secret-key-for-testing-purposes-only';
    }

    public function testSupportsHmacAlgorithms(): void
    {
        self::assertTrue(SignerFactory::isSupported('HS256'));
        self::assertTrue(SignerFactory::isSupported('HS384'));
        self::assertTrue(SignerFactory::isSupported('HS512'));
    }

    public function testDoesNotSupportOtherAlgorithms(): void
    {
        self::assertTrue(SignerFactory::isSupported('RS256')); // RSA is supported
        self::assertTrue(SignerFactory::isSupported('ES256')); // ECDSA is supported
        self::assertFalse(SignerFactory::isSupported('INVALID'));
    }

    public function testSignWithHS256(): void
    {
        $signer = SignerFactory::create('HS256');
        $data = 'test.data';
        $signature = $signer->sign($data, $this->secret);

        self::assertIsString($signature);
        self::assertNotEmpty($signature);

        // 验证签名
        self::assertTrue($signer->verify($data, $signature, $this->secret));
    }

    public function testSignWithHS384(): void
    {
        $signer = SignerFactory::create('HS384');
        $data = 'test.data';
        $signature = $signer->sign($data, $this->secret);

        self::assertIsString($signature);
        self::assertNotEmpty($signature);

        // 验证签名
        self::assertTrue($signer->verify($data, $signature, $this->secret));
    }

    public function testSignWithHS512(): void
    {
        $signer = SignerFactory::create('HS512');
        $data = 'test.data';
        $signature = $signer->sign($data, $this->secret);

        self::assertIsString($signature);
        self::assertNotEmpty($signature);

        // 验证签名
        self::assertTrue($signer->verify($data, $signature, $this->secret));
    }

    public function testSignWithUnsupportedAlgorithm(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        SignerFactory::create('INVALID');
    }

    public function testVerifyWithInvalidSignature(): void
    {
        $signer = SignerFactory::create('HS256');
        $data = 'test.data';
        $signature = $signer->sign($data, $this->secret);

        // 使用错误的数据验证
        self::assertFalse($signer->verify('wrong.data', $signature, $this->secret));

        // 使用错误的密钥验证
        self::assertFalse($signer->verify($data, $signature, 'wrong-secret'));

        // 使用错误的签名验证
        self::assertFalse($signer->verify($data, 'wrong-signature', $this->secret));
    }

    public function testSignatureConsistency(): void
    {
        $signer = SignerFactory::create('HS256');
        $data = 'test.data';

        // 同样的数据和密钥应该产生相同的签名
        $signature1 = $signer->sign($data, $this->secret);
        $signature2 = $signer->sign($data, $this->secret);

        self::assertEquals($signature1, $signature2);
    }

    public function testDifferentAlgorithmsProduceDifferentSignatures(): void
    {
        $data = 'test.data';

        $signer256 = SignerFactory::create('HS256');
        $signer384 = SignerFactory::create('HS384');
        $signer512 = SignerFactory::create('HS512');

        $signature256 = $signer256->sign($data, $this->secret);
        $signature384 = $signer384->sign($data, $this->secret);
        $signature512 = $signer512->sign($data, $this->secret);

        self::assertNotEquals($signature256, $signature384);
        self::assertNotEquals($signature256, $signature512);
        self::assertNotEquals($signature384, $signature512);
    }

    public function testValidKeyHandling(): void
    {
        $signer = SignerFactory::create('HS256');

        // 测试有效密钥
        self::assertTrue($signer->isValidKey($this->secret));

        // 测试空密钥
        self::assertFalse($signer->isValidKey(''));
    }
}
