<?php

namespace JPGauthier\SocialiteProviders\OIDC;

use SocialiteProviders\Manager\SocialiteWasCalled;

class OIDCExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('oidc', Provider::class);
    }
}
