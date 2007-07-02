<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4 foldmethod=marker: */

/**
 * Storage driver for use against PEAR website
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This source file is subject to version 3.01 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_01.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category   Authentication
 * @package    Auth
 * @author     Yavor Shahpasov <yavo@netsmart.com.cy>
 * @author     Adam Ashley <aashley@php.net>
 * @copyright  2001-2006 The PHP Group
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version    CVS: $Id$
 * @link       http://pear.php.net/package/Auth
 * @since      File available since Release 1.3.0
 */

/**
 * Include Auth_Container base class
 */
require_once 'Auth/Container.php';

/**
 * Storage driver for authenticating against PEAR website
 *
 * This driver provides a method for authenticating against the pear.php.net
 * authentication system.
 *
 * @category   Authentication
 * @package    Auth
 * @author     Yavor Shahpasov <yavo@netsmart.com.cy>
 * @author     Adam Ashley <aashley@php.net>
 * @copyright  2001-2006 The PHP Group
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 * @version    Release: @package_version@  File: $Revision$
 * @link       http://pear.php.net/package/Auth
 * @since      Class available since Release 1.3.0
 */
class Auth_Container_Pear extends Auth_Container
{

    // {{{ Auth_Container_Pear() [constructor]

    /**
     * Constructor
     *
     * Currently does nothing
     *
     * @return void
     */
    function Auth_Container_Pear()
    {

    }

    // }}}
    // {{{ fetchData()

    /**
     * Get user information from pear.php.net
     *
     * This function uses the given username and password to authenticate
     * against the pear.php.net website
     *
     * @param string    Username
     * @param string    Password
     * @return mixed    Error object or boolean
     */
    function fetchData($username, $password)
    {
        $this->log('Auth_Container_PEAR::fetchData() called.', AUTH_LOG_DEBUG);
        $salt = file_get_contents('http://pear.php.net/rest-login.php/getsalt');
        print "<pre>\n"
            ."-------HTTP_RESPONSE_HEADER-------\n"
            .print_r($http_response_header, true)."\n"
            ."-------HTTP_RESPONSE_HEADER-------\n"
            ."</pre>\n";
        $cookies = array_values(preg_grep('/Set-Cookie:/', $http_response_header));
        preg_match('/PHPSESSID=(.+); /', $cookies[0], $session);
        $pass = md5($salt . md5($password));
        $opts = array('http' => array(
            'method' => 'POST',
            'header' => "Content-type: application/x-www-form-urlencoded\r\n"
                       ."Cookie: PHPSESSID=" . $session[1] . "\r\n",
            'content' => http_build_query(array('username' => $username, 'password' => $pass))
        ));
        print "<pre>\n"
            ."-----------HEADER-----------\n"
            .print_r($opts, true)."\n"
            ."-----------HEADER-----------\n"
            ."</pre>\n";
        $context = stream_context_create($opts);
        $result = file_get_contents('http://pear.php.net/rest-login.php/validate', false, $context);
        print "<pre>\n"
            ."-------HTTP_RESPONSE_HEADER-------\n"
            .print_r($http_response_header, true)."\n"
            ."-------HTTP_RESPONSE_HEADER-------\n"
            ."</pre>\n";
        print "<pre>\n"
            ."-----------RESULT-----------\n"
            .$result."\n"
            ."-----------RESULT-----------\n"
            ."</pre>\n";

        // Error Checking howto ???
        if ($result == '8 Login OK') {
            $this->activeUser = $username;
            return true;
        }
        return false;
    }

    // }}}

}
?>
