<?php

namespace Cpluscc\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Cpluscc\OAuth2\Client\Exception\AmazonIdentityProviderException;
use Psr\Http\Message\ResponseInterface;

class Misskey extends AbstractProvider
{

    /**
     * Returns the base URL for authorizing a client.
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://sso.cplus.app/oauth2/auth';
    }

    /**
     * Returns the base URL for requesting an access token.
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://sso.cplus.app/oauth2/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://sso.cplus.app/userinfo?' . http_build_query(['access_token' => $token->getToken()]);
    }

    /**
     * Returns the default scopes used by this provider.
     */
    protected function getDefaultScopes(): array
    {
        return [
            'profile'
        ];
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            throw new MisskeyIdentityProviderException(
                $data['error'] ?: $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     */
    protected function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface
    {
        return new MisskeyResourceOwner($response);
    }
}
