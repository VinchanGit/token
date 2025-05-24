<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\SignatureString;

class Payload
{
    /**
     * Issuer.
     * @var string 令牌的签发者（如服务端域名或标识）
     */
    protected string $iss;

    /**
     * Subject.
     * @var string 令牌的主题（通常是用户唯一标识）
     */
    protected string $sub;

    /**
     * Audience.
     * @var string 令牌的目标接收方（如服务端 API 的 URL）
     */
    protected string $aud;

    /**
     * Expiration Time.
     * @var string 令牌的过期时间（UTC 时间戳，单位为秒）
     */
    protected string $exp;

    /**
     * Not Before.
     * @var string 令牌的生效时间（UTC 时间戳，在此之前令牌无效）
     */
    protected string $nbf;

    /**
     * Issued At.
     * @var string 令牌的签发时间（UTC 时间戳）
     */
    protected string $iat;

    /**
     * JWT ID.
     * @var string 令牌的唯一标识（用于防重放攻击）
     */
    protected string $jti;

    /**
     * Extends.
     * @var array 拓展字段
     */
    protected array $extends = [];

    public function getIss(): string
    {
        return $this->iss;
    }

    public function setIss(string $iss): Payload
    {
        $this->iss = $iss;
        return $this;
    }

    public function getSub(): string
    {
        return $this->sub;
    }

    public function setSub(string $sub): Payload
    {
        $this->sub = $sub;
        return $this;
    }

    public function getAud(): string
    {
        return $this->aud;
    }

    public function setAud(string $aud): Payload
    {
        $this->aud = $aud;
        return $this;
    }

    public function getExp(): string
    {
        return $this->exp;
    }

    public function setExp(string $exp): Payload
    {
        $this->exp = $exp;
        return $this;
    }

    public function getNbf(): string
    {
        return $this->nbf;
    }

    public function setNbf(string $nbf): Payload
    {
        $this->nbf = $nbf;
        return $this;
    }

    public function getIat(): string
    {
        return $this->iat;
    }

    public function setIat(string $iat): Payload
    {
        $this->iat = $iat;
        return $this;
    }

    public function getJti(): string
    {
        return $this->jti;
    }

    public function setJti(string $jti): Payload
    {
        $this->jti = $jti;
        return $this;
    }

    public function getExtends(): array
    {
        return $this->extends;
    }

    public function setExtends(array $extends): Payload
    {
        $this->extends = $extends;
        return $this;
    }
}
