<?php

namespace SocialiteProviders\OIDC;

use GuzzleHttp\RequestOptions;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

/**
 * Class Provider.
 *
 * @see https://docs.whmcs.com/OpenID_Connect_Developer_Guide
 */
class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'OIDC';

    /**
     * {@inheritdoc}
     */
    protected $scopes = [

        // required; to indicate that the application intends to use OIDC to verify the user's identity
        // Returns the sub claim, which uniquely identifies the user. 
        // In an ID Token : iss, aud, exp, iat, and at_hash claims will also be present.
        'openid',

        // Returns the email claim, which contains the user's email address
        // email, email_verified (which is a boolean indicating whether the email address was verified by the user).
        'email',

        // Returns claims that represent basic profile information
        // name, family_name, given_name, middle_name, nickname, picture, and updated_at.
        'profile',

        // Returns user's roles
        // crha-member, crha-member-type-1, crha-member-status-reg, etc.
        'roles',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['url'];
    }

    /**
     * @return array OpenID data for OIDC
     */
    protected function getOpenidConfig()
    {
        static $data = null;

        if ($data === null) {
            $configUrl = $this->getConfig('url').'/.well-known/openid-configuration';

            $response = $this->getHttpClient()->get($configUrl);

            $data = json_decode((string) $response->getBody(), true);
        }

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            $this->getOpenidConfig()['authorization_endpoint'],
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function buildAuthUrlFromBase($url, $state)
    {
        $nonce = 'test';

        return $url.'?'.http_build_query(
            [
                'client_id'     => $this->clientId,
                'redirect_uri'  => $this->redirectUrl,
                // https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660
                'response_type' => 'code id_token',
                'scope'         => $this->formatScopes($this->scopes, $this->scopeSeparator),
                'state'         => $state,
                'nonce'         => $nonce,
            ],
            '',
            '&',
            $this->encodingType
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getOpenidConfig()['token_endpoint'];
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS     => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => array_merge(
                $this->getTokenFields($code),
                [
                    'grant_type' => 'authorization_code',
                ]
            ),
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * Get the user_info URL for the provider.
     *
     * @return string
     */
    protected function getUserInfoUrl()
    {
        return $this->getOpenidConfig()['userinfo_endpoint'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            $this->getUserInfoUrl().'?'.http_build_query(
                [
                    'access_token' => $token,
                ]
            ),
            [
                RequestOptions::HEADERS => [
                    'Accept' => 'application/json',
                ],
            ]
        );

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map(
            [
                'avatar'   => null,
                'email'    => $user['email'],
                'id'       => $user['sub'],
                'name'     => $user['name'],
                'nickname' => null,
            ]
        );
    }
}
