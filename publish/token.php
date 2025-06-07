<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */
return [
    'default' => [
        // 签名算法
        'algorithm' => env('JWT_ALGORITHM', 'HS256'),

        // 密钥配置
        'secret_key' => env('JWT_SECRET', 'your-secret-key'),

        // Token过期时间（秒）
        'ttl' => (int) env('JWT_TTL', 3600),

        // 签发者
        'issuer' => env('JWT_ISSUER', 'vinchan/token'),

        // 受众
        'audience' => env('JWT_AUDIENCE', 'api'),

        // 自动刷新阈值（剩余时间少于此值时可刷新）
        'refresh_threshold' => (int) env('JWT_REFRESH_THRESHOLD', 300),
    ],

    // 可以定义多个配置用于不同场景
    'admin' => [
        'algorithm' => env('JWT_ADMIN_ALGORITHM', 'HS256'),
        'secret_key' => env('JWT_ADMIN_SECRET', 'your-admin-secret-key'),
        'ttl' => (int) env('JWT_ADMIN_TTL', 7200), // 2小时
        'issuer' => env('JWT_ADMIN_ISSUER', 'vinchan/token-admin'),
        'audience' => env('JWT_ADMIN_AUDIENCE', 'admin'),
        'refresh_threshold' => (int) env('JWT_ADMIN_REFRESH_THRESHOLD', 600),
    ],
];
