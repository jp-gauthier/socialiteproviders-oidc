<?php

namespace SocialiteProviders\OIDC;

use InvalidArgumentException;

class InvalidNonceException extends InvalidArgumentException
{
    /**
     * Render the exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function render($request)
    {
        $message = "La vérification du nonce a échoué. Veuillez réessayer.";
        $url = route_membre('login');
        return redirect($url)->withErrors(['msg' => $message]);
    }
}
