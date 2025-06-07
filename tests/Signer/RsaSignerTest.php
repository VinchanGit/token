<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token\Signer;

use Vinchan\Token\Exception\SignatureException;
use Vinchan\Token\Signer\RsaSigner;
use VinchanTest\Token\TestCase;

/**
 * @internal
 * @coversNothing
 */
class RsaSignerTest extends TestCase
{
    private RsaSigner $signer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->signer = new RsaSigner();
    }

    public function testSignWithRS256(): void
    {
        $data = 'test-data';
        $privateKey = $this->getRsaPrivateKey();
        $signer = new RsaSigner('RS256');

        $signature = $signer->sign($data, $privateKey);

        self::assertIsString($signature);
        self::assertNotEmpty($signature);
    }

    public function testVerifyValidSignature(): void
    {
        $data = 'test-data';
        $privateKey = $this->getRsaPrivateKey();
        $publicKey = $this->getRsaPublicKey();
        $signer = new RsaSigner('RS256');

        $signature = $signer->sign($data, $privateKey);
        $isValid = $signer->verify($data, $signature, $publicKey);

        self::assertTrue($isValid);
    }

    public function testVerifyInvalidSignature(): void
    {
        $data = 'test-data';
        $publicKey = $this->getRsaPublicKey();
        $invalidSignature = 'invalid-signature';
        $signer = new RsaSigner('RS256');

        $isValid = $signer->verify($data, $invalidSignature, $publicKey);

        self::assertFalse($isValid);
    }

    public function testSignWithInvalidKey(): void
    {
        $this->expectException(SignatureException::class);
        $signer = new RsaSigner('RS256');

        $signer->sign('test', 'invalid-key');
    }

    public function testDifferentAlgorithms(): void
    {
        $data = 'test-data';
        $privateKey = $this->getRsaPrivateKey();

        $signerRS256 = new RsaSigner('RS256');
        $signerRS384 = new RsaSigner('RS384');
        $signerRS512 = new RsaSigner('RS512');

        $signatureRS256 = $signerRS256->sign($data, $privateKey);
        $signatureRS384 = $signerRS384->sign($data, $privateKey);
        $signatureRS512 = $signerRS512->sign($data, $privateKey);

        self::assertNotEquals($signatureRS256, $signatureRS384);
        self::assertNotEquals($signatureRS256, $signatureRS512);
        self::assertNotEquals($signatureRS384, $signatureRS512);
    }
}
