<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\Contract;

/**
 * JWT 签名器接口
 * 定义所有签名器必须实现的方法.
 */
interface SignerInterface
{
    /**
     * 检查算法是否被支持
     */
    public function supports(string $algorithm): bool;

    /**
     * 验证密钥是否对当前算法有效.
     */
    public function isValidKey(string $key): bool;

    /**
     * 对数据进行签名.
     */
    public function sign(string $data, string $key): string;

    /**
     * 验证签名是否有效.
     */
    public function verify(string $data, string $signature, string $key): bool;
}
