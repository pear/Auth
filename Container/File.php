<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
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
// | Authors: Stefan Ekman <stekman@sedata.org>                           |
// |          Martin Jansen <mj@php.net>                                  |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once "File/Passwd.php";
require_once "Auth/Container.php";
require_once "PEAR.php";

/**
 * Storage driver for fetching login data from an encrypted password file.
 *
 * This storage container can handle Unix style passwd, .htaccess, and
 * CVS pserver passwd files.
 *
 * @author   Stefan Ekman <stekman@sedata.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_File extends Auth_Container
{
    /**
     * File_Passwd object
     * @var object
     */
    var $pwfile;

    // {{{ Constructor

    /**
     * Constructor of the container class
     *
     * @param  $filename   string filename for a passwd type file
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_File($filename)
    {
        if (!is_file($filename)) {
            return new PEAR_Error("Illegal filename.", 41, PEAR_ERROR_DIE);
        }

        if (!$this->pwfile = new File_Passwd($filename,0)) {
            return new PEAR_Error("Error while reading file contents.", 41, PEAR_ERROR_DIE);
        }

        $this->pwfile->close();
    }

    // }}}
    // {{{ fetchData()

    /**
     * Get user information from pwfile
     *
     * @param   string Username
     * @param   string Password
     * @return  boolean
     */
    function fetchData($username, $password)
    {
        $result = $this->pwfile->verifyPassword($username, $password);
        
        if ($result) {
            Auth::SetAuth($username);
        }

        return $result;
    }

    // }}}
    // {{{ listUsers()
    
    function listUsers()
    {
        $users = $this->pwfile->listUsers();

        foreach ($users as $key => $value) {
            $retVal[] = array("username" => $key, "password" => $value);
        }

        return $retVal;
    }

    // }}}
}
?>
