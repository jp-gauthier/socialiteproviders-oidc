# WHMCS

```bash
composer require jp-gauthier/socialiteproviders-oidc
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

## Specific configuration

Follow [this link](https://docs.whmcs.com/OpenID_Connect) to create OpenID credentials in your WHMCS installation

### Add configuration to `config/services.php`

```php
'oidc' => [
    'client_id' => env('OPENID_CLIENT_ID'),
    'client_secret' => env('OPENID_CLIENT_SECRET'),
    'redirect' => env('OPENID_REDIRECT_URI'),
    'url' => env('OPENID_URL'), // URL of your installation
],
```

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        'SocialiteProviders\\OIDC\\OIDCExtendSocialite@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('oidc')->redirect();
```

### Returned User fields

- `id`
- `name`
- `email`

More fields are available under the `user` subkey:

```php
$user = Socialite::driver('oidc')->user();

$locale = $user->user['locale'];
$email_verified = $user->user['email_verified'];
```
