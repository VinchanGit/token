<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace Vinchan\Token\SignatureString;

class Header
{
    /**
     * Algorithm.
     * @var string 指定签名算法
     */
    protected string $alg;

    /**
     * Type.
     * @var string 令牌类型
     */
    protected string $typ;

    /**
     * Key ID.
     * @var string 密钥标识符
     */
    protected string $kid;

    /**
     * 内容类型.
     * @var string Content Type
     */
    protected string $cty;

    /**
     * JWK Set URL.
     * @var string 公钥集 URL
     */
    protected string $jku;

    /**
     * JSON Web Key.
     * @var string 直接嵌入公钥
     */
    protected string $jwk;

    /**
     * X.509 Certificate URL.
     * @var string X.509 证书链 URL
     */
    protected string $x5u;

    /**
     * X.509 Certificate Chain.
     * @var string 直接嵌入 X.509 证书链
     */
    protected string $x5c;

    /**
     * X.509 SHA-1 Thumbprint.
     * @var string X.509 证书的 SHA-1 指纹
     */
    protected string $x5t;

    /**
     * X.509 SHA-256 Thumbprint.
     * @var string X.509 证书的 SHA-256 指纹
     */
    protected string $x5t_S256;
}
