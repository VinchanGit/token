<?php

namespace Vinchan\Token\Contracts;

interface EncipherInterface
{
    public function encode(string $string);

    public function decode(string $string);
}