<?php

namespace BashOIDC\OAuth2\Client\OpenIDConnect;


use InvalidArgumentException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use BashOIDC\OAuth2\Client\OpenIDConnect\Exception\TokenIntrospectionException;
use BashOIDC\OAuth2\Client\OpenIDConnect\Exception\CertificateEndpointException;
use BashOIDC\OAuth2\Client\OpenIDConnect\Exception\InvalidUrlException;
use BashOIDC\OAuth2\Client\OpenIDConnect\Exception\WellKnownEndpointException;

abstract class AbstractOIDCProvider extends AbstractProvider
{
    private const OPTION_WELL_KNOWN_URL = 'well_known_endpoint';

    protected Discovery $discovery;

    /**
     * Compatible with league\oauth2-client 2.x
     * Clients written for Identity Providers that support OpenID Connect Discovery can extend this class instead of 'League\OAuth2\Client\Provider\AbstractProvider'
     * Required options are:
     *   'well_known_endpoint' - The URI of the provider's .well-known/openid-configuration service
     */
    public function __construct(array $options, array $collaborators = [])
    {
        $this->assertRequiredOptions($options);

        parent::__construct($options, $collaborators);

        // Create and run the discovery object
        try {
            $this->discovery = new Discovery($this, $options[self::OPTION_WELL_KNOWN_URL]);
        } catch (CertificateEndpointException|InvalidUrlException|WellKnownEndpointException|\JsonException $e) {
        }
    }

    public function getDiscovery(): Discovery
    {
        return $this->discovery;
    }

    /**
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getResourceOwnerDetailsUrl()
     */
    public function getResourceOwnerDetailsUrl(AccessTokenInterface $token): ?string
    {
        return $this->discovery->getUserInfoEndpoint();
    }

    /**
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAuthorizationUrl()
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->discovery->getAuthorizationEndpoint();
    }

    /**
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAccessTokenUrl()
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->discovery->getTokenEndpoint();
    }

    /**
     * Decode a token (either locally or remotely if introspection endpoint is available)
     * @throws TokenIntrospectionException
     */
    public function introspectToken($token, array $queryParams = [], bool $decode_locally = true): ParsedToken
    {
        $jwt_allowed_algs = [
            'ES384', 'ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
        ];

        $resolved_algs = array_intersect($this->discovery->getUserInfoSigningAlgValuesSupported(), $jwt_allowed_algs);

        if ($decode_locally) {
            // Decode locally using cached JWK
            try {
                return new ParsedToken(json_encode(JWT::decode($token, JWK::parseKeySet($this->discovery->getPublicKey()), $resolved_algs), JSON_THROW_ON_ERROR));
            } catch (\Exception $e) {
                throw new TokenIntrospectionException($e->getMessage(), null, $e);
            }
        } else {
            // Try the provider token introspection endpoint
            try {

                $introspectionEndpoint = $this->discovery->getIntrospectionEndpoint();

                if (!is_null($introspectionEndpoint)) {
                    $query_params = [
                        "client_id" => $this->clientId,
                        "client_secret" => $this->clientSecret,
                        "token" => $token
                    ];

                    if (!empty($queryParams)) {
                        $query_params = array_merge($query_params, $queryParams);
                    }

                    $http_query_string = http_build_query($query_params);

                    $httpRequest = $this->getRequestFactory()->getRequest(AbstractProvider::METHOD_POST, $introspectionEndpoint,
                        [
                            'Content-Type' => 'application/x-www-form-urlencoded',
                            'Accept' => 'application/json'
                        ], $http_query_string);

                    $httpResponse = $this->getResponse($httpRequest);

                    if ($httpResponse->getStatusCode() === 200) {
                        return new ParsedToken((string)$httpResponse->getBody());
                    }

                    throw new TokenIntrospectionException($httpResponse->getReasonPhrase(), $httpResponse->getStatusCode());
                }

                throw new TokenIntrospectionException("Invalid Token Introspection Endpoint");
            } catch (\Exception $e) {
                throw new TokenIntrospectionException($e->getMessage(), null, $e);
            }
        }
    }

    protected function getRequiredOptions(): array
    {
        return [
            self::OPTION_WELL_KNOWN_URL,
        ];
    }

    private function assertRequiredOptions(array $options): void
    {
        $missing = array_diff_key(array_flip($this->getRequiredOptions()), $options);

        if (!empty($missing)) {
            throw new InvalidArgumentException(
                'Required options not defined: ' . implode(', ', array_keys($missing))
            );
        }
    }
}
