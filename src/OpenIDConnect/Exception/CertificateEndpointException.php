<?php

namespace BashOIDC\OAuth2\Client\OpenIDConnect\Exception;

class CertificateEndpointException extends \Exception
{
    public function __construct($message = null, $code = null, $previous = null)
    {
        parent::__construct('Certificate endpoint error ['.$message.']', $code, $previous);
    }
}
