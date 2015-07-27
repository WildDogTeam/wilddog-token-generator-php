<?php
/*
 * Wilddog token生成工具。
 *
 * License信息请参见：https://github.com/WildDogTeam/wilddog-token-generator-php/blob/master/LICENSE
 */
namespace Wilddog\Token;

require dirname(__FILE__) . '/JWT.php';

/**
 * 为wilddog应用生成用于认证用户的token。
 */
class TokenGenerator
{
    // 字节为单位
    const MAX_UID_SIZE   = 256;
    const MAX_TOKEN_SIZE = 1024;

    /**
     * token数据.
     *
     * @var mixed[]
     */
    private $data;

    /**
     * 可选配置
     *
     * @var mixed[]
     */
    private $options;

    /**
     * Wilddog超级密钥
     *
     * @var string
     */
    private $secret;

    /**
     *
     * @param string $secret Wilddog超级密钥。
     *
     * @throws TokenException 超级密钥不合法时抛出。
     */
    public function __construct($secret)
    {
        if (!is_string($secret)) {
            throw new TokenException(
                sprintf('The Wilddog secret must be a string, %s given.', gettype($secret))
            );
        }
        $this->secret = $secret;
        $this->data   = [];

        // 默认配置参数
        $this->options = [
            'admin'     => false,
            'debug'     => false,
            'expires'   => null,
            'notBefore' => null,
        ];
    }

    /**
     * 设置token数据
     *
     * @param array $data 一个array，必须包含uid字段，除非admin为true。
     *
     * @return static
     */
    public function setData(array $data)
    {
        $this->data = $data;
        return $this;
    }

    /**
     * 设置多个可选配置参数。
     *
     * @see setOption()
     *
     * @param array $options
     *
     * @throws TokenException
     *
     * @return static
     */
    public function setOptions(array $options)
    {
        foreach ($options as $name => $value) {
            $this->setOption($name, $value);
        }
        return $this;
    }

    /**
     * 设置一个可选配置参数。
     *
     * @param string $name  参数名。
     * @param mixed  $value 参数值。
     *
     * @throws TokenException
     *
     * @return static
     */
    public function setOption($name, $value)
    {
        if (!array_key_exists($name, $this->options)) {
            throw new TokenException(
                sprintf(
                    'Unsupported option "%s". Valid options are: ', $name, implode(', ', array_keys($this->options))
                )
            );
        }
        switch ($name) {
            case 'admin':
            case 'debug':
                if (!is_bool($value)) {
                    throw new TokenException(
                        sprintf('Invalid option "%s". Expected %s, but %s given', $name, 'bool', gettype($value))
                    );
                }
                break;
            case 'expires':
            case 'notBefore':
                if (!is_int($value) && !($value instanceof \DateTime)) {
                    throw new TokenException(
                        sprintf(
                            'Invalid option "%s". Expected %s, but %s given',
                            $name, 'int or DateTime', gettype($value)
                        )
                    );
                }
                if (is_int($value)) {
                    $value = \DateTime::createFromFormat('U', $value);
                }
                break;
        }
        $this->options[$name] = $value;
        return $this;
    }

    /**
     * 生成token。
     *
     * @throws TokenException
     *
     * @return string JWT token.
     */
    public function create()
    {
        $this->validate();
        $claims        = $this->processOptions();
        $claims['d']   = $this->data;
        $claims['v']   = 0;
        $claims['iat'] = time();
        try {
            $token = JWT::encode($claims, $this->secret, 'HS256');
        } catch (\Exception $e) {
            throw new TokenException($e->getMessage(), null, $e);
        }
        if (($tokenSize = mb_strlen($token, '8bit')) > static::MAX_TOKEN_SIZE) {
            throw new TokenException(
                sprintf('The generated token is larger than %d bytes (%d)', static::MAX_TOKEN_SIZE, $tokenSize)
            );
        }
        return $token;
    }

    /**
     * @return array The claims.
     */
    private function processOptions()
    {
        $claims = [];
        foreach ($this->options as $name => $value) {
            switch ($name) {
                case 'expires':
                    if ($value instanceof \DateTime) {
                        $claims['exp'] = $value->getTimestamp();
                    }
                    break;
                case 'notBefore':
                    if ($value instanceof \DateTime) {
                        $claims['nbf'] = $value->getTimestamp();
                    }
                    break;
                default:
                    $claims[$name] = $value;
                    break;
            }
        }
        return $claims;
    }

    /**
     * 检查token数据和options合法性。 token数据必须包含uid字段，除非option中admin为true。
     *
     * @throws TokenException
     */
    private function validate()
    {
        if (false === $this->options['admin'] && !array_key_exists('uid', $this->data)) {
            throw new TokenException('No uid provided in data and admin option not set.');
        }
        if (array_key_exists('uid', $this->data)) {
            $this->validateUid($this->data['uid']);
        }
    }

    /**
     * 校验uid
     *
     * @param string $uid
     *
     * @throws TokenException
     */
    private function validateUid($uid)
    {
        if (!is_string($uid)) {
            throw new TokenException(sprintf('The uid must be a string, %s given.', gettype($uid)));
        }
        $uidSize = mb_strlen($uid, '8bit');
        if ($uidSize > static::MAX_UID_SIZE) {
            throw new TokenException(
                sprintf('The provided uid is longer than %d bytes (%d).', static::MAX_UID_SIZE, $uidSize)
            );
        }
        if (0 === $uidSize) {
            throw new TokenException('The provided uid is empty.');
        }
    }
}