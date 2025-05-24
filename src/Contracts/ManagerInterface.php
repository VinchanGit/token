<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Contracts;

interface ManagerInterface
{
    public function login(Authenticatable $authenticatable);
}
