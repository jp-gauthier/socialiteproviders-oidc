<?php

namespace SocialiteProviders\OIDC;

use GuzzleHttp\RequestOptions;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\InvalidStateException;
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
        // email, email_verified
        'email',

        // Returns claims that represent basic profile information
        // name, family_name, given_name, middle_name, nickname, picture, updated_at
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
     * Indicates if the nonce should be utilized.
     *
     * @var bool
     */
    protected $usesNonce = true;
    
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
        return $url.'?'.http_build_query(
            [
                'client_id'     => $this->clientId,
                'redirect_uri'  => $this->redirectUrl,
                // https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660
                'response_type' => 'code id_token',
                // Sends the token response as a form post instead of a fragment encoded redirect
                'response_mode' => 'form_post',
                'scope'         => $this->formatScopes($this->scopes, $this->scopeSeparator),
                'state'         => $state,
                // https://auth0.com/docs/authorization/flows/mitigate-replay-attacks-when-using-the-implicit-flow
                'nonce'         => $this->getCurrentNonce(),
            ],
            '',
            '&',
            $this->encodingType
        );
    }
    
    /**
     * Redirect the user of the application to the provider's authentication screen.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function redirect()
    {
        $state = null;
        $nonce = null;

        if ($this->usesState()) {
            $this->request->session()->put('state', $state = $this->getState());
        }

        if ($this->usesNonce()) {
            $this->request->session()->put('nonce', $nonce = $this->getNonce());
        }

        if ($this->usesPKCE()) {
            $this->request->session()->put('code_verifier', $codeVerifier = $this->getCodeVerifier());
        }

        return new RedirectResponse($this->getAuthUrl($state));
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
        echo "getUserByToken";
        die();

        /*
        $response = $this->getHttpClient()->post(
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
        */
    }

    /**
     * Receive data from auth/callback route
     * code, id_token, scope, state, session_state
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException("Callback data contains an invalid state.", 401);
        }

        // Decrypt JWT token
        $payload = $this->decodeJWT($this->request->get('id_token'));
        $this->user = $this->mapUserToObject((array) $payload);

        /**
         * Send the code to get an access_token
         * Response contains : id_token, access_token, expires_in, token_type, scope
         */
        $response = $this->getAccessTokenResponse($this->getCode());
        $token = Arr::get($response, 'access_token');

        dd($this->user);
        
        return $this->user->setToken($token)
                    // ->setRefreshToken(Arr::get($response, 'refresh_token'))
                    ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map(
            [
                'id'        => $user['sub'],
                'idp'       => $user['idp'],
                'name'      => $user['name'],
                'email'     => $user['email'],
                'role'      => $user['role'],
            ]
        );
    }
    
    /**
     * Determine if the provider is operating with nonce.
     *
     * @return bool
     */
    protected function usesNonce()
    {
        return $this->usesNonce;
    }

    /**
     * Get the string used for nonce.
     *
     * @return string
     */
    protected function getNonce()
    {
        return Str::random(40);
    }
    
    /**
     * Get the current string used for nonce.
     *
     * @return string
     */
    protected function getCurrentNonce()
    {
        $nonce = null;

        if ($this->request->session()->has('nonce')) {
            $nonce = $this->request->session()->get('nonce');
        }
        
        return $nonce;
    }
    
    /**
     * Determine if the current token has a mismatching "nonce".
     *
     * @return bool
     */
    protected function isInvalidNonce($nonce)
    {
        if (!$this->usesNonce()) {
            return false;
        }

        return ! (strlen($nonce) > 0 && $nonce === $this->getCurrentNonce());
    }

    /**
     * Determine if this is an invalid ID Token
     * Validate with c_hash
     * Ref: https://auth0.com/docs/authorization/flows/call-api-hybrid-flow
     *
     * @return bool
     */
    protected function isInvalidIDToken($jwt, $alg, $c_hash)
    {
        return false;

        // 1. Using the hash algorithm specified in the alg claim in the ID Token header, hash the octets of the ASCII representation of the code.
        $bit = '256'; // 256/384/512 
        if ($alg != 'none') {
            $bit = substr($alg, 2, 3);
        }
        $jwt_ascii = Str::ascii($jwt);
        $binary_mode = true;
        $jwt_hashed = hash('sha'.$bit, $jwt_ascii, $binary_mode);
        
        // 2. Base64url-encode the left-most half of the hash.
        $len = ((int)$bit)/16;
        $left_part = substr($jwt_hashed, 0, $len);
        $result = $this->base64URLEncode($left_part);

        // 3. Check that the result matches the c_hash value.
        echo "RESULT : ".$result;
        echo "<br>";
        echo "C_HASH : ".$c_hash;

        die();
    }

    protected function decodeJWT($jwt)
    {
        try {

            list($jwt_header, $jwt_payload, $jwt_signature) = explode(".", $jwt);

            // alg, kid, typ, x5t
            $header = json_decode(base64_decode($jwt_header));

            // nbf, exp, iss, aud, nonce, iat, c_hash, sid, auth_time, amr
            // sub (dossier), idp (crha-member)
            // name, role (array), given_name, family_name, email
            $payload = json_decode(base64_decode($jwt_payload));

        } catch (\Exception $e) {
            throw new InvalidIDTokenException("Failed to parse ID Token.", 401);
        }
        
        if ($this->isInvalidIDToken($jwt, $header->alg, $payload->c_hash)) {
            throw new InvalidNonceException("Failed to verify ID Token.", 401);
        }
        
        if ($this->isInvalidNonce($payload->nonce)) {
            throw new InvalidNonceException("The JWT contains an invalid nonce.", 401);
        }

        return $payload;
    }

    /**
     * Base64 + URLEncode a string
     * Ref: https://github.com/ritou/php-Akita_OpenIDConnect/blob/master/src/Akita/OpenIDConnect/Util/Base64.php
     */
    private function base64URLEncode($str)
    {
        $enc = base64_encode($str);
        $enc = rtrim($enc, "=");
        $enc = strtr($enc, "+/", "-_");
        return $enc;
    }
}
