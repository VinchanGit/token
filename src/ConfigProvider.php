<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token;

use Vinchan\Token\Contract\SignerInterface;
use Vinchan\Token\Signer\EcdsaSigner;
use Vinchan\Token\Signer\HmacSigner;
use Vinchan\Token\Signer\RsaSigner;
use Vinchan\Token\Signer\SignerFactory;

/**
 * Hyperf 配置提供者
 * 负责注册依赖注入和发布配置文件.
 */
class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                SignerInterface::class => HmacSigner::class,
                SignerFactory::class => SignerFactory::class,
                HmacSigner::class => HmacSigner::class,
                RsaSigner::class => RsaSigner::class,
                EcdsaSigner::class => EcdsaSigner::class,
                Authenticatable::class => Authenticatable::class,
                TokenManager::class => TokenManager::class,
            ],
            'publish' => [
                [
                    'id' => 'token',
                    'description' => 'JWT Token 配置文件',
                    'source' => __DIR__ . '/../publish/token.php',
                    'destination' => defined('BASE_PATH') ? BASE_PATH . '/config/autoload/token.php' : 'config/autoload/token.php',
                ],
            ],
        ];
    }
}
