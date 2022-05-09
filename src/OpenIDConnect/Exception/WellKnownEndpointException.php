<?php

namespace BashOIDC\OAuth2\Client\OpenIDConnect\Exception;

class WellKnownEndpointException extends \Exception
{
    public function __construct($message = '', $code = null, $previous = null)
    {
        parent::__construct('OpenID Connect Discovery Exception [' . $message . ']', $code, $previous);
    }
}
