# JWT Token Library (vinchan/token)

一个简洁而强大的PHP JWT库，专为现代PHP应用设计。

## 特性

- 🚀 **极简设计** - 只有2个核心类，API简洁直观
- 🛡️ **类型安全** - 完整的PHP 8.2+ 类型声明
- 🔐 **多算法支持** - 支持HMAC、RSA、ECDSA算法族
- ⚙️ **配置驱动** - 支持多环境配置，灵活切换
- 🎯 **零依赖** - 除PHP标准库和OpenSSL外无额外依赖
- ✅ **全面测试** - 单元测试覆盖率高，质量可靠

## 安装

```bash
composer require vinchan/token
```

## 快速开始

### 基础用法

```php
use Vinchan\Token\Authenticatable;
use Vinchan\Token\TokenManager;

// 创建用户信息
$user = new Authenticatable('user123', [
    'name' => 'John Doe',
    'role' => 'admin',
    'email' => 'john@example.com'
]);

// 生成token
$token = TokenManager::create()
    ->payload($user)
    ->ttl(3600)        // 1小时过期
    ->generate('your-secret-key');

// 验证token
$isValid = TokenManager::create()->verify($token, 'your-secret-key');

// 获取用户信息
$userInfo = TokenManager::create()->info($token, 'your-secret-key');
if ($userInfo) {
    echo $userInfo->getId();        // user123
    echo $userInfo->get('name');    // John Doe
    echo $userInfo->get('role');    // admin
}
```

### 配置文件方式

创建配置文件 `config/autoload/token.php`：

```php
return [
    'default' => [
        'algorithm' => 'HS256',
        'secret_key' => env('JWT_SECRET', 'your-secret-key'),
        'ttl' => 3600,
        'issuer' => 'your-app',
        'audience' => 'api',
    ],
    'admin' => [
        'algorithm' => 'HS512',
        'secret_key' => env('JWT_ADMIN_SECRET', 'admin-secret'),
        'ttl' => 7200,
        'issuer' => 'admin-panel',
    ],
];
```

使用配置：

```php
// 使用默认配置
$token = TokenManager::create()
    ->payload($user)
    ->generate(); // 自动从配置获取密钥

// 使用指定配置
$adminToken = TokenManager::with('admin')
    ->payload($user)
    ->generate();

// 验证时也会自动使用配置
$isValid = TokenManager::create()->verify($token);
$userInfo = TokenManager::create()->info($token);
```

## 核心类

### TokenManager

主要的JWT处理类，提供流畅的API：

```php
$manager = TokenManager::create()
    ->payload($authenticatable)    // 设置载荷
    ->algorithm('HS256')          // 设置算法
    ->ttl(3600)                   // 设置过期时间
    ->issuer('my-app')            // 设置签发者
    ->audience('api')             // 设置受众
    ->config('admin')             // 指定配置键
    ->generate($secretKey);       // 生成token
```

**主要方法：**
- `generate(?string $key = null): string` - 生成JWT token
- `verify(string $token, ?string $key = null): bool` - 验证token有效性
- `info(string $token, ?string $key = null): ?Authenticatable` - 获取token信息

**静态工厂方法：**
- `TokenManager::create()` - 创建实例
- `TokenManager::with(string $configKey)` - 使用指定配置创建实例

### Authenticatable

用户身份信息值对象：

```php
// 创建用户信息（ID必须）
$user = new Authenticatable('user123', [
    'name' => 'John',
    'role' => 'admin',
    'permissions' => ['read', 'write']
]);

// 访问数据
$user->getId();                    // user123
$user->get('name');               // John
$user->get('role', 'guest');      // admin (带默认值)
$user->getData();                 // 获取所有额外数据
$user->toArray();                 // 转为数组

// 从数组创建
$user = Authenticatable::fromArray([
    'id' => 'user123',
    'name' => 'John',
    'role' => 'admin'
]);
```

## 支持的算法

### HMAC算法族
```php
TokenManager::create()->algorithm('HS256')->payload($user)->generate('secret');
TokenManager::create()->algorithm('HS384')->payload($user)->generate('secret');
TokenManager::create()->algorithm('HS512')->payload($user)->generate('secret');
```

### RSA算法族
```php
// 生成时使用私钥
$token = TokenManager::create()
    ->algorithm('RS256')
    ->payload($user)
    ->generate($privateKey);

// 验证时使用公钥
$isValid = TokenManager::create()
    ->algorithm('RS256')
    ->verify($token, $publicKey);
```

### ECDSA算法族
```php
TokenManager::create()->algorithm('ES256')->payload($user)->generate($privateKey);
TokenManager::create()->algorithm('ES384')->payload($user)->generate($privateKey);
TokenManager::create()->algorithm('ES512')->payload($user)->generate($privateKey);
```

## 高级用法

### 自定义Claims

```php
$user = new Authenticatable('user123', [
    'name' => 'John',
    'role' => 'admin',
    'department' => 'IT',
    'permissions' => ['read', 'write', 'delete']
]);

$token = TokenManager::create()
    ->payload($user)
    ->issuer('my-company')
    ->audience('internal-api')
    ->ttl(7200)
    ->generate($key);
```

### 错误处理

```php
try {
    $token = TokenManager::create()
        ->payload($user)
        ->generate($key);
        
    $userInfo = TokenManager::create()->info($token, $key);
    
} catch (\Vinchan\Token\Exception\SignatureException $e) {
    // 签名相关错误
} catch (\Vinchan\Token\Exception\ExpiredException $e) {
    // token过期
} catch (\Vinchan\Token\Exception\InvalidTokenException $e) {
    // token格式无效
}
```

### 多环境配置

```php
// 开发环境
$devToken = TokenManager::with('dev')
    ->payload($user)
    ->generate();

// 生产环境  
$prodToken = TokenManager::with('production')
    ->payload($user)
    ->generate();

// 管理员环境
$adminToken = TokenManager::with('admin')
    ->payload($user)
    ->generate();
```

## 在Hyperf中使用

### 1. 发布配置文件

```bash
php bin/hyperf.php vendor:publish vinchan/token
```

### 2. 配置环境变量

```env
JWT_SECRET=your-super-secret-key-here
JWT_TTL=3600
JWT_ALGORITHM=HS256
```

### 3. 在控制器中使用

```php
<?php

namespace App\Controller;

use Vinchan\Token\Authenticatable;
use Vinchan\Token\TokenManager;

class AuthController
{
    public function login()
    {
        // 验证用户凭据...
        
        $user = new Authenticatable((string)$userId, [
            'username' => $username,
            'role' => $userRole,
        ]);
        
        $token = TokenManager::create()
            ->payload($user)
            ->generate();
            
        return ['token' => $token];
    }
    
    public function profile(string $token)
    {
        $user = TokenManager::create()->info($token);
        
        if (!$user) {
            throw new UnauthorizedException('Invalid token');
        }
        
        return [
            'id' => $user->getId(),
            'username' => $user->get('username'),
            'role' => $user->get('role'),
        ];
    }
}
```

## API参考

### TokenManager类

| 方法 | 说明 | 参数 | 返回值 |
|------|------|------|--------|
| `create()` | 静态工厂方法 | 无 | `TokenManager` |
| `with(string $configKey)` | 使用指定配置创建 | 配置键名 | `TokenManager` |
| `payload(Authenticatable $auth)` | 设置载荷 | 用户对象 | `self` |
| `algorithm(string $alg)` | 设置算法 | 算法名称 | `self` |
| `ttl(int $seconds)` | 设置过期时间 | 秒数 | `self` |
| `issuer(string $iss)` | 设置签发者 | 签发者 | `self` |
| `audience(string $aud)` | 设置受众 | 受众 | `self` |
| `config(string $key)` | 设置配置键 | 配置键 | `self` |
| `generate(?string $key)` | 生成token | 密钥(可选) | `string` |
| `verify(string $token, ?string $key)` | 验证token | token, 密钥(可选) | `bool` |
| `info(string $token, ?string $key)` | 获取信息 | token, 密钥(可选) | `?Authenticatable` |

### Authenticatable类

| 方法 | 说明 | 参数 | 返回值 |
|------|------|------|--------|
| `__construct(string $id, array $data)` | 构造函数 | ID, 数据数组 | - |
| `fromArray(array $data)` | 从数组创建 | 包含id的数组 | `Authenticatable` |
| `getId()` | 获取ID | 无 | `string` |
| `get(string $key, mixed $default)` | 获取字段值 | 字段名, 默认值 | `mixed` |
| `getData()` | 获取所有数据 | 无 | `array` |
| `toArray()` | 转为数组 | 无 | `array` |

## 测试

```bash
composer test
```

## 许可证

MIT License. 详见 [LICENSE](LICENSE) 文件。
