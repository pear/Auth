<?php
//
// +----------------------------------------------------------------------+
// | PHP version 4.0                                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2001 The PHP Group                                |
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

require_once "Auth/Container.php";
require_once "PEAR.php";

/**
 * Storage driver for fetching login data from a textfile
 *
 * @author   Martin Jansen <mj@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_File extends Auth_Container
{

    /**
     * Content of the password file
     * @var string
     */
    var $content = "";

    // {{{ Constructor

    /**
     * Constructor of the container class
     *
     * @param  $dsn   string connection data or DB object
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_File($filename)
    {
        if (!is_file($filename)) {
            return new PEAR_Error("Illegal filename.", 41, PEAR_ERROR_DIE);
        }

        if (!$this->content = @file($filename)) {
            return new PEAR_Error("Error while reading file contents.", 41, PEAR_ERROR_DIE);
        }
    }

    // }}}
    // {{{ fetchData()

    /**
     * Get user information from textfile
     *
     * @param   string Username
     * @param   string Password
     * @return  boolean
     */
    function fetchData($username, $password)
    {
        foreach ($this->content as $value) {

            list($file_username, $file_password) = explode(":", $value);

            if ($file_username == $username) {

                $file_password = trim($file_password);

                switch (strlen($file_password)) {
                    /**
                     * MD5 encryption
                     */
                    case 32 : {
                        $compare_password = md5($password);
                        break;
                    }

                    default : {
                        $compare_password = $password;
                    }
                }

                if ($file_password == $compare_password) {
                    Auth::setAuth($username);
                    return true;
                }
            }
        }

        return false;
    }

    // }}}
}
?>
