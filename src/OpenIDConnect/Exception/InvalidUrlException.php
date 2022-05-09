<?php

namespace BashOIDC\OAuth2\Client\OpenIDConnect\Exception;

class InvalidUrlException extends \Exception
{
    public function __construct($message = '', $code = null, $previous = null)
    {
        parent::__construct('Invalid URL [' . $message . ']', $code, $previous);
    }
}

