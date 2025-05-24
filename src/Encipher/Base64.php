<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Encipher;

use Vinchan\Token\Contracts\EncipherInterface;

class Base64 implements EncipherInterface
{
    public function encode(string $string): string
    {
        return base64_encode($string);
    }

    public function decode(string $string): bool|string
    {
        return base64_decode($string);
    }
}
