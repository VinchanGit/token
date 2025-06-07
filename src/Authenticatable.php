<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token;

/**
 * 认证用户值对象
 * 表示可认证的用户身份信息，包含必需的ID和可选的附加数据.
 */
class Authenticatable
{
    /**
     * 构造函数.
     *
     * @param string $id 用户唯一标识符（必需）
     * @param array $data 附加用户数据（可选）
     * @throws \InvalidArgumentException 当ID为空时抛出异常
     */
    public function __construct(
        private readonly string $id,
        private readonly array $data = []
    ) {
        if (empty($this->id)) {
            throw new \InvalidArgumentException('ID 不能为空');
        }
    }

    /**
     * 获取用户ID.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * 获取指定键的值，支持默认值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * 获取所有附加数据.
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * 转为数组格式.
     */
    public function toArray(): array
    {
        return array_merge(['id' => $this->id], $this->data);
    }

    /**
     * 从数组创建 Authenticatable 实例.
     *
     * @param array $data 必须包含 'id' 键的数组
     * @throws \InvalidArgumentException 当数组中缺少id键时抛出异常
     */
    public static function fromArray(array $data): self
    {
        if (! isset($data['id'])) {
            throw new \InvalidArgumentException('数组必须包含 id 键');
        }

        $id = (string) $data['id'];
        unset($data['id']);

        return new self($id, $data);
    }
}
