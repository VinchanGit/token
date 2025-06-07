<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token;

use Vinchan\Token\Authenticatable;

/**
 * @internal
 * @coversNothing
 */
class AuthenticatableTest extends TestCase
{
    public function testCreateWithId(): void
    {
        $auth = new Authenticatable('user123');

        self::assertEquals('user123', $auth->getId());
        self::assertEquals([], $auth->getData());
    }

    public function testCreateWithIdAndData(): void
    {
        $data = ['name' => 'John', 'email' => 'john@example.com'];
        $auth = new Authenticatable('user123', $data);

        self::assertEquals('user123', $auth->getId());
        self::assertEquals($data, $auth->getData());
        self::assertEquals('John', $auth->get('name'));
        self::assertEquals('john@example.com', $auth->get('email'));
    }

    public function testGetWithDefault(): void
    {
        $auth = new Authenticatable('user123', ['name' => 'John']);

        self::assertEquals('John', $auth->get('name'));
        self::assertEquals('default', $auth->get('missing', 'default'));
        self::assertNull($auth->get('missing'));
    }

    public function testToArray(): void
    {
        $data = ['name' => 'John', 'email' => 'john@example.com'];
        $auth = new Authenticatable('user123', $data);

        $expected = ['id' => 'user123', 'name' => 'John', 'email' => 'john@example.com'];
        self::assertEquals($expected, $auth->toArray());
    }

    public function testFromArray(): void
    {
        $data = ['id' => 'user123', 'name' => 'John', 'email' => 'john@example.com'];
        $auth = Authenticatable::fromArray($data);

        self::assertEquals('user123', $auth->getId());
        self::assertEquals('John', $auth->get('name'));
        self::assertEquals('john@example.com', $auth->get('email'));
    }

    public function testCreateWithEmptyId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ID 不能为空');

        new Authenticatable('');
    }

    public function testFromArrayWithoutId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('数组必须包含 id 键');

        Authenticatable::fromArray(['name' => 'John']);
    }
}
