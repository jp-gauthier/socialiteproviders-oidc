<?php

namespace SocialiteProviders\OIDC;

use Exception;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
// use Laravel\Socialite\Two\InvalidStateException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
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

    public $configurations = null;

    /**
     * {@inheritdoc}
     */
    protected $scopes = [

        // required; to indicate that the application intends to use OIDC to verify the user's identity
        // Returns the sub claim, which uniquely identifies the user. 
        // Also presents in an ID Token : iss, aud, exp, iat, c_hash.
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
    
    protected $loginPage = '';

    /**
     * Indicates if the nonce should be utilized.
     *
     * @var bool
     */
    protected $usesNonce = true;
    
    public function getLoginPage()
    {
        return route($this->getConfig('login_route'));
    }

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return [
            'url',
            'login_route'
        ];
    }

    /**
     * @return array OpenID data for OIDC
     */
    protected function getOpenidConfig()
    {
        if ($this->configurations === null) {
            $configUrl = $this->getConfig('url').'/.well-known/openid-configuration';
            
            $response = $this->getHttpClient()->get($configUrl);

            $this->configurations = json_decode((string) $response->getBody(), true);
        }

        return $this->configurations;
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
        return $url.'?'.http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            
            // Implicit flow response_type
            // https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660
            'response_type' => 'code id_token',

            // Sends the token response as a form post instead of a fragment encoded redirect
            'response_mode' => 'form_post',
            
            // Always show login form
            // https://auth0.com/docs/login/max-age-reauthentication
            'prompt' => 'login',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        if ($this->usesNonce()) {
            // Implicit flow nonce
            // https://auth0.com/docs/authorization/flows/mitigate-replay-attacks-when-using-the-implicit-flow
            $fields['nonce'] = $this->getCurrentNonce();
        }

        if ($this->usesPKCE()) {
            $fields['code_challenge'] = $this->getCodeChallenge();
            $fields['code_challenge_method'] = $this->getCodeChallengeMethod();
        }

        return array_merge($fields, $this->parameters);
    }

    /**
     * {@inheritdoc}
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
    }

    /**
     * Receive data from auth/callback route
     * code, id_token, scope, state, session_state
     */
    public function user()
    {
        // Test mode
        if (app()->environment() !== 'production' && !is_null(request()->route('no_dossier'))) {
            $payload = [
                'sub'           => request()->route('no_dossier'),
            ];
            $this->user = $this->mapUserToObject((array) $payload);
        }

        if ($this->user) {
            return $this->user;
        }
        
        if ($this->hasInvalidState()) {
            throw new InvalidStateException("Callback: invalid state.", 401);
        }
        
        // Decrypt JWT token
        $payload = $this->decodeJWT(
            $this->request->get('id_token'), 
            $this->request->get('code')
        );

        if ($this->hasEmptyEmail($payload)) {
            throw new EmptyEmailException("JWT: User has no email.", 401);
        }

        $this->user = $this->mapUserToObject((array) $payload);
        
        /**
         * Send the code to get an access_token
         * Response contains : id_token, access_token, expires_in, token_type, scope
         */
        /*
        $response = $this->getAccessTokenResponse($this->getCode());
        $token = Arr::get($response, 'access_token');
        $userDetails = $this->getUserByToken($token);
        return $this->user->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
        */

        return $this->user;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map(
            [
                'sub'           => $user['sub'],

                'email'         => $user['email'] ?? null,
                'name'          => $user['name'] ?? null,
                'given_name'    => $user['given_name'] ?? null,
                'family_name'   => $user['family_name'] ?? null,

                'idp'           => $user['idp'] ?? null,
                'role'          => $user['role'] ?? null,
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
     * nonce must be validated to prevent replay attacks
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
    
    protected function hasEmptyEmail($payload)
    {
        if (!isset($payload->email) || strlen($payload->email) == 0) {
            return true;
        }
        return false;
    }

    /**
     * Determine if the code is valid
     * c_hash must correspond to the encoded code
     * Ref: https://auth0.com/docs/authorization/flows/call-api-hybrid-flow
     * Ref: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
     * (3.3.2.10.  Authorization Code Validation)
     * 
     * @return bool
     */
    protected function isInvalidCode($code, $alg, $c_hash)
    {
        // 1. Using the hash algorithm specified in the alg claim in the ID Token header, hash the octets of the ASCII representation of the code.
        $bit = '256'; // 256/384/512 
        if ($alg != 'none') {
            $bit = substr($alg, 2, 3);
        }
        $code_ascii = Str::ascii($code);
        $binary_mode = true;
        $code_hashed = hash('sha'.$bit, $code_ascii, $binary_mode);
        
        // 2. Base64url-encode the left-most half of the hash.
        $len = strlen($code_hashed)/2;
        $left_part = substr($code_hashed, 0, $len);
        $result = $this->base64url_encode($left_part);
        
        // 3. Check that the result matches the c_hash value.
        return $result !== $c_hash;
    }

    protected function decodeJWT($jwt, $code)
    {
        try {
            list($jwt_header, $jwt_payload, $jwt_signature) = explode(".", $jwt);

            // alg, kid, typ, x5t
            $header = json_decode($this->base64url_decode($jwt_header));

            // nbf, exp, iss, aud, nonce, iat, c_hash, sid, auth_time, amr
            // sub (dossier), idp (crha-member)
            // name, role (array), given_name, family_name, email
            $payload = json_decode($this->base64url_decode($jwt_payload));

        } catch (\Exception $e) {
            throw new InvalidIDTokenException("JWT: Failed to parse.", 401);
        }

        if ($this->isInvalidCode($code, $header->alg, $payload->c_hash)) {
            throw new InvalidCodeException("JWT: Failed to verify code vs c_hash.", 401);
        }

        if ($this->isInvalidNonce($payload->nonce)) {
            throw new InvalidNonceException("JWT: Contains an invalid nonce.", 401);
        }

        return $payload;
    }

    private function base64url_encode($data)
    { 
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
    }

    private function base64url_decode($data)
    { 
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)); 
    }
}
