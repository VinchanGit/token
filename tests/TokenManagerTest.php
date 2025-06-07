<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token;

use Vinchan\Token\Authenticatable;
use Vinchan\Token\Exception\SignatureException;
use Vinchan\Token\TokenManager;

/**
 * @internal
 * @coversNothing
 */
class TokenManagerTest extends TestCase
{
    public function testCreateTokenManagerWithPayload(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John', 'role' => 'admin']);
        $manager = TokenManager::create()->payload($auth);

        $token = $manager->generate($this->getHmacSecret());

        self::assertIsString($token);
        self::assertNotEmpty($token);
    }

    public function testGenerateAndVerifyToken(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);
        $manager = TokenManager::create()->payload($auth);
        $key = $this->getHmacSecret();

        $token = $manager->generate($key);
        $isValid = $manager->verify($token, $key);

        self::assertTrue($isValid);
    }

    public function testGenerateWithoutExplicitKey(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        // 这个测试模拟没有配置文件的情况，会使用默认密钥
        $manager = TokenManager::create()->payload($auth);
        $token = $manager->generate(); // 不传key，使用配置默认值

        self::assertIsString($token);
        self::assertNotEmpty($token);
    }

    public function testVerifyInvalidToken(): void
    {
        $manager = TokenManager::create();

        $isValid = $manager->verify('invalid.token.here', $this->getHmacSecret());

        self::assertFalse($isValid);
    }

    public function testGetInfoFromToken(): void
    {
        $originalAuth = new Authenticatable('user123', ['name' => 'John', 'role' => 'admin']);
        $manager = TokenManager::create()->payload($originalAuth);
        $key = $this->getHmacSecret();

        $token = $manager->generate($key);
        $retrievedAuth = $manager->info($token, $key);

        self::assertInstanceOf(Authenticatable::class, $retrievedAuth);
        self::assertEquals('user123', $retrievedAuth->getId());
        self::assertEquals('John', $retrievedAuth->get('name'));
        self::assertEquals('admin', $retrievedAuth->get('role'));
    }

    public function testInfoFromInvalidToken(): void
    {
        $manager = TokenManager::create();

        $retrievedAuth = $manager->info('invalid.token.here', $this->getHmacSecret());

        self::assertNull($retrievedAuth);
    }

    public function testFluentAPI(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);
        $key = $this->getHmacSecret();

        $token = TokenManager::create()
            ->payload($auth)
            ->algorithm('HS256')
            ->ttl(3600)
            ->issuer('test-app')
            ->audience('test-audience')
            ->generate($key);

        self::assertIsString($token);
        self::assertNotEmpty($token);

        $manager = TokenManager::create()->algorithm('HS256');
        self::assertTrue($manager->verify($token, $key));

        $retrievedAuth = $manager->info($token, $key);
        self::assertEquals('user123', $retrievedAuth->getId());
    }

    public function testConfigurationSupport(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        // 测试使用不同的配置key
        $manager = TokenManager::create()
            ->config('admin')
            ->payload($auth);

        $token = $manager->generate($this->getHmacSecret());

        self::assertIsString($token);
        self::assertNotEmpty($token);
    }

    public function testWithStaticMethod(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        // 测试静态工厂方法
        $token = TokenManager::with('admin')
            ->payload($auth)
            ->generate($this->getHmacSecret());

        self::assertIsString($token);
        self::assertNotEmpty($token);
    }

    public function testDifferentAlgorithms(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        $token256 = TokenManager::create()
            ->payload($auth)
            ->algorithm('HS256')
            ->generate($this->getHmacSecret());

        $token384 = TokenManager::create()
            ->payload($auth)
            ->algorithm('HS384')
            ->generate($this->getHmacSecret());

        self::assertNotEquals($token256, $token384);

        $manager256 = TokenManager::create()->algorithm('HS256');
        $manager384 = TokenManager::create()->algorithm('HS384');

        self::assertTrue($manager256->verify($token256, $this->getHmacSecret()));
        self::assertTrue($manager384->verify($token384, $this->getHmacSecret()));
    }

    public function testRSAAlgorithm(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        $token = TokenManager::create()
            ->payload($auth)
            ->algorithm('RS256')
            ->generate($this->getRsaPrivateKey());

        $manager = TokenManager::create()->algorithm('RS256');
        self::assertTrue($manager->verify($token, $this->getRsaPublicKey()));

        $retrievedAuth = $manager->info($token, $this->getRsaPublicKey());
        self::assertEquals('user123', $retrievedAuth->getId());
        self::assertEquals('John', $retrievedAuth->get('name'));
    }

    public function testGenerateWithoutPayload(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('载荷是必需的');

        TokenManager::create()->generate($this->getHmacSecret());
    }

    public function testTTLFromConfig(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        // 测试TTL配置（由于没有实际配置文件，这里主要测试API）
        $manager = TokenManager::create()->payload($auth);
        $token = $manager->generate($this->getHmacSecret());

        // 验证token包含过期时间
        $retrievedAuth = $manager->info($token, $this->getHmacSecret());
        self::assertInstanceOf(Authenticatable::class, $retrievedAuth);
    }
}
