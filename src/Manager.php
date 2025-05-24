<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token;

use Vinchan\Token\Contracts\Authenticatable;
use Vinchan\Token\Contracts\ManagerInterface;

class Manager implements ManagerInterface
{
    protected Authenticatable $authenticatable;

    public function login(Authenticatable $authenticatable) {}

    public function logout() {}

    public function refresh() {}

    public function check() {}

    public function user() {}

    public function getId()
    {
        return $this->authenticatable->getId();
    }

    public function getExtendValue(?string $key = null)
    {
        if (empty($key)) {
            return $this->authenticatable;
        }

        return $this->authenticatable->{$key} ?? null;
    }
}
