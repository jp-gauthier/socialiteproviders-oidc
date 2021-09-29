<?php

namespace SocialiteProviders\OIDC;

use InvalidArgumentException;
use Laravel\Socialite\Facades\Socialite;

class InvalidStateException extends InvalidArgumentException
{
    /**
     * Render the exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function render($request)
    {
        $message = "La vérification de l'état de la demande a échoué. Veuillez réessayer.";
        $url = Socialite::driver('oidc')->getLoginPage();
        return redirect($url)->withErrors(['msg' => $message]);
    }
}