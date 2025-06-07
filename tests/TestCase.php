<?php

declare(strict_types=1);
/**
 * Copyright (c) The Vinchan , Distributed under the software license
 */

namespace VinchanTest\Token;

use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /**
     * Get test HMAC secret.
     */
    protected function getHmacSecret(): string
    {
        return 'your-256-bit-secret-key-for-testing-purposes-only';
    }

    /**
     * Get test RSA private key.
     */
    protected function getRsaPrivateKey(): string
    {
        return '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuqlAJ7DC8drlmKbpVAxS+vmAw02d7VVgXMPOKunElE1YSh0u
1PhzIVTJVh4wVk0cJZhE9fyg+1mGwCejSjNmn5SXncfKBVdaX+WEDt7UYpjbcyiM
X2SsNDxapXOwKtjw5q47Z61lEBpdaW5xerBhyuUdprqyAholdsOxZbRo+jevaXnW
gvZhsNZmIGvQeF9aEoXLn6bg6u692om6odnO4rN/nRRqyx655soTGkkj8Sr1Xova
GTR4m1Fq3RumPx37Cp14Mr4zaRgt/GxcMXERE4ug3amBJ53qN91NZRisF60AiFMD
c32yk2qVxb7e+l6/uQxNj7m1P3YE2BrWQDa26wIDAQABAoIBAEahytv6ABqCqUSV
TE94hmHfzcCZezwWhWs00KveX3t6tQD+f/0osnAXZERJEiNl9FOphdbLLKNP4jSO
CzUFtDyIfsK+mgxhXJpTACCcYyOYEdpGqq9iKeNuPyLCXxQnmSjBH0uBCnAIefZu
S1SQr8CV6B1yIe+3sxt4u4TvupWLnJFsRicDYw0ibR/z7ps6pQJTg6peQk4Ng+Um
rXs8FShWBw8pTctVCqCBWmlGqzOdqafIYu2FO3luznv7fLVJMTgXodUUgdLNVZIM
2eu/c2O1ADI1REGDJU+0Arg8DMollKORGz+QDGJ6QOJIuQ4vq5dRtsPZVeu1m/tD
xzbC+hkCgYEA8Dlj1BrXarklQlb4Wil+v86fzbca3n+7zS4Apc9F3dBT7Y45ZGHO
jYCRTN1+R6kdxAM2rElA7/UzPvJhWBuOQ8hjowMaKNBKfCRkIRm4ChE6RP6iM1Op
oMpiSxx0yqIk4wAvRnADQi/qHCltSCLrDT6Zuob9EqOl/KZdxuuzqn0CgYEAxute
DtfMxbiyM0xocRVAdaEUJWJ+Rd2xdZYD3epbM9OGZs1/Nnf73a5JbRzPmqe8nndb
9tKaR/01x/YlMVcQWHMI2dWcROiGwFAQSHcP54BrZPv4LRCmOeSiskxzpB4qEze0
l7BlTvJyuJiTVTghMBFobQzNloJ21Y0MQ2dxO4cCgYBwKdu6xW2fnyMOfp0nPAi6
djeXTc915B5EBx62TLlKgGMvoCCcBi7zUvyE70ZvHz+OrhFxECMJ52suEO3yvasH
ayFak7A7LkYZAMTfz6pmyPR0EpCZdo7VTKnoeDjwBBVFCGkKcnKTDNw6mf00mVk2
rewJc83mThLKjMNshdE14QKBgA8f4EPyppA2Dd6Wpa5Ldl47RCPfjEhVpeOR53Nd
GVgkciio4U5L6yucz9prAWH59P57htOKic6FcyxkC8nnm8eN35NoiXw3zd8bd1F7
NAtfGUtRWTpb9LecKb6yz2wgGwThDGsoL1vEVXKxryognW1hNXZtLciO3Og51D/f
wp1LAoGBAOVAQcs2ojmVBxAa1B6uXFUMAlVuBHKc9X9SDWqbjNlOB+VI2h/G4mxE
9ZPPIh06rVIZGtVpm0ObtHmwa0ByD7WbY/RIeubs3V4bNoWmtbVqill+Hadd+qu4
WU2pqiheN1BVIW68LFdYz3D5Ncy+pS6YUuyV7OfE8jSYiXla1V1j
-----END RSA PRIVATE KEY-----';
    }

    /**
     * Get test RSA public key.
     */
    protected function getRsaPublicKey(): string
    {
        return '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqlAJ7DC8drlmKbpVAxS
+vmAw02d7VVgXMPOKunElE1YSh0u1PhzIVTJVh4wVk0cJZhE9fyg+1mGwCejSjNm
n5SXncfKBVdaX+WEDt7UYpjbcyiMX2SsNDxapXOwKtjw5q47Z61lEBpdaW5xerBh
yuUdprqyAholdsOxZbRo+jevaXnWgvZhsNZmIGvQeF9aEoXLn6bg6u692om6odnO
4rN/nRRqyx655soTGkkj8Sr1XovaGTR4m1Fq3RumPx37Cp14Mr4zaRgt/GxcMXER
E4ug3amBJ53qN91NZRisF60AiFMDc32yk2qVxb7e+l6/uQxNj7m1P3YE2BrWQDa2
6wIDAQAB
-----END PUBLIC KEY-----';
    }

    /**
     * Get test ECDSA private key (P-256).
     */
    protected function getEcdsaPrivateKey(): string
    {
        return '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGYsbbykSf0M/PozNYhW1GUtsxsXNN2xHqHZ+J5cI/dOoAoGCCqGSM49
AwEHoUQDQgAEGLB6v2NsHNAFMuUsnjkbHOOPH+PBef0aHaqllt2eI/Vbk95d/F6A
dd880iHtIy6pANsbRQUhwUsyhZDN2a5vWA==
-----END EC PRIVATE KEY-----';
    }

    /**
     * Get test ECDSA public key (P-256).
     */
    protected function getEcdsaPublicKey(): string
    {
        return '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGLB6v2NsHNAFMuUsnjkbHOOPH+PB
ef0aHaqllt2eI/Vbk95d/F6Add880iHtIy6pANsbRQUhwUsyhZDN2a5vWA==
-----END PUBLIC KEY-----';
    }

    /**
     * Get test payload data.
     */
    protected function getTestPayload(): array
    {
        return [
            'user_id' => 123,
            'username' => 'testuser',
            'email' => 'test@example.com',
            'iat' => time(),
            'exp' => time() + 3600, // 1 hour
        ];
    }
}
