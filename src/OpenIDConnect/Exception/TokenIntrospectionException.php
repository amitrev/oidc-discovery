<?php

namespace BashOIDC\OAuth2\Client\OpenIDConnect\Exception;

class TokenIntrospectionException extends \Exception
{
    public function __construct($message = '', $code = null, $previous = null)
    {
        parent::__construct('Token Introspection Exception [' . $message . ']', $code, $previous);
    }
}

