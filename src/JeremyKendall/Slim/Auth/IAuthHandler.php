<?php

/**
 * Slim Auth
 *
 * @link      https://github.com/Chris911/slim-api-auth Canonical source repo
 * @copyright Copyright (c) 2013 Christophe Naud-Dulude
 * @license   https://github.com/Chris911/slim-api-auth/blob/master/LICENSE MIT
 */

namespace JeremyKendall\Slim\Auth;

/**
 * Slim Auth Handler
 * This class handles failure or success of the authentication
 */
interface IAuthHandler
{
    /**
    * Called if the authentication is a success
    */
    public function pass();

    /**
    * Called if the authentication is a failure
    */
    public function fail();
}
