<?php

namespace SocialiteProviders\CRHA;

use SocialiteProviders\Manager\SocialiteWasCalled;

class CRHAExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('crha', Provider::class);
    }
}
