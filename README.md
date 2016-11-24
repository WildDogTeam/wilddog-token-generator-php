# Wilddog Token Generator - PHP

Wilddog允许用户使用自定义Token进行终端用户认证。Token采用的是安全的JSON Web Token(JWT)格式。
注意：本分支只支持Wilddog Auth1.0版本API 不支持Wilddog Auth2.0版本API。


## 依赖

Wilddog Token Generator for php 需要运行在php 5.4或更高版本上。
依赖：
* php-mbstring。


## 安全提示

由于token的生成需要Wilddog应用的超级密钥, 因此token生成工作只能在信任的服务器上进行。
绝对不要将Wilddog超级密钥嵌入到客户端应用中，以便于保障超级密钥不会泄漏。


## 生成token

要生成token, 必须要使用wilddog的超级密钥。使用浏览器进入应用的控制面板，在“超级密钥”tab中可以找到应用的超级密钥。
示例代码：

```php
use Wilddog\Token\TokenException;
use Wilddog\Token\TokenGenerator;

try {
    $generator = new TokenGenerator('<YOUR_WILDDOG_SECRET>');
    $token = $generator
        ->setData(array('uid' => 'exampleID'))
        ->create();
} catch (TokenException $e) {
    echo "Error: ".$e->getMessage();
}

echo $token;
```

setData()函数设置token的payload部分。payload必须含有"uid"字段。uid字段必须是字符串类型，长度小于256字节。
最终生成的token必须小于1024字节。


## Token Options

可选的options有：

* **expires** (number or DateTime) - 时间戳 (秒为单位) 或者一个 `DateTime`，代表的是token的有效期至。超过这个时间之后，此token将失效。

* **notBefore** (number or DateTime) - 时间戳 (秒为单位) 或者一个 `DateTime`，代表的是在此时间之前，这个token是无效的。

* **admin** (boolean) - 如果设置为"true"，那么用这个token认证过的客户端将获得管理员权限，规则表达式不会对admin权限的客户端生效.
admin权限的客户端拥有对所有数据的读写权限。


下面是设置options的示例代码:

```php
use Wilddog\Token\TokenGenerator;

$generator = new TokenGenerator('<YOUR_WILDDOG_SECRET>');

// Using setOption()
$token = $generator
    ->setOption('admin', true)
    ->setData(array('uid' => 'exampleID'))
    ->create();

// Using setOptions()
$token = $generator
    ->setOptions(array(
        'admin' => true
    ))
    ->setData(array('uid' => 'exampleID'))
    ->create();
```


## Changelog

#### 1.0.0 - 2015-07-28
- Initial release
