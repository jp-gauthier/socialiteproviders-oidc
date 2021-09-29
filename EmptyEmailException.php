<?php

namespace SocialiteProviders\OIDC;

use InvalidArgumentException;
use Laravel\Socialite\Facades\Socialite;

class EmptyEmailException extends InvalidArgumentException
{
    /**
     * Render the exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function render($request)
    {
        $message = "Votre profil ne contient pas d'adresse courriel. Veuillez en spécifier une dans votre dossier de membre et vous assurer de compléter le processus de changement de nom d'usager.";
        $url = Socialite::driver('oidc')->getLoginPage();
        return redirect($url)->withErrors(['msg' => $message]);
    }
}