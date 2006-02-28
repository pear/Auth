<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2003 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.02 of the PHP license,      |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Martin Jansen <mj@php.net>                                  |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once 'Auth.php';

/**
 * Anonymouse Authentication
 * 
 * This class provides anonymous authentication
 * if username and password were not supplied
 *
 * @author   Yavor Shahpasov <yavo@netsmart.com.cy>
 * @author   Adam Ashley <aashley@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Anonymous extends Auth 
{

    // {{{ properties

    /**
     * Whether to allow anonymous authentication
     *
     * @var boolean
     */
    var $allow_anonymous = true;

    /**
     * Username to use for anonymous user
     *
     * @var string
     */
    var $anonymous_username = 'anonymous';

    // }}}

    // {{{ Auth_Anonymous() [constructor]
    
    /**
     * Pass all parameters to Parent Auth class
     * 
     * Set up the storage driver.
     *
     * @param string    Type of the storage driver
     * @param mixed     Additional options for the storage driver
     *                  (example: if you are using DB as the storage
     *                   driver, you have to pass the dsn string here)
     *
     * @param string    Name of the function that creates the login form
     * @param boolean   Should the login form be displayed if neccessary?
     * @return void
     * @see Auth::Auth()
     */
    function Auth_Anonymous($storageDriver, $options = '', $loginFunction = '', $showLogin = true) {
        parent::Auth($storageDriver, $options, $loginFunction, $showLogin);
    }

    // }}}
    // {{{ login()
    
    /**
     * Login function
     * 
     * If no username & password is passed then login as the username
     * provided in $this->anonymous_username else call standard login()
     * function.
     *
     * @return void
     * @access private
     * @see Auth::login()
     */
    function login() {
        if (   $this->allow_anonymous 
            && empty($this->username) 
            && empty($this->password) ) {
            $this->setAuth($this->anonymous_username);
            if (is_callable($this->loginCallback)) {
                call_user_func_array($this->loginCallback, array($this->username, $this) );
            }
        } else {
            // Call normal login system
            parent::login();
        }
    }

    // }}}
    // {{{ forceLogin()
    
    /**
     * Force the user to login
     *
     * Calling this function forces the user to provide a real username and
     * password before continuing.
     *
     * @return void
     */
    function forceLogin() {
        $this->allow_anonymous = false;
        if( !empty($this->session['username']) && $this->session['username'] == $this->anonymous_username ) {
            $this->logout();
        }
    }

    // }}}

}

?>
