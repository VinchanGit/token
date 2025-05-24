<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */
use function Hyperf\Support\env;

return [
    'header_name' => env('HEADER_NAME', 'Authorization'),
];
