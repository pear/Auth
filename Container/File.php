<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2002 The PHP Group                                |
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
// |          Mika Tuupola <tuupola@appelsiini.net>                       |
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
            return PEAR::raiseError("Illegal filename.", 41, PEAR_ERROR_DIE);
        }

        if (!$this->pwfile = new File_Passwd($filename,0)) {
            return PEAR::raiseError("Error while reading file contents.", 41, PEAR_ERROR_DIE);
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
        
        return $result;
    }

    // }}}
    // {{{ listUsers()
    
    function listUsers()
    {
        $users = $this->pwfile->listUsers();

        if (!is_array($users)) {
            return array();
        }

        foreach ($users as $key => $value) {
            $cvsuser = $this->pwfile->getCvsUser($key);
            $retVal[] = array("username" => $key, 
                              "password" => $value,
                              "cvsuser"  => $cvsuser);
        }

        return $retVal;
    }

    // }}}

    /**
     * Add a new user to the storage container
     *
     * @param string Username
     * @param string Password
     * @param mixed  CVS username
     *
     * @return boolean
     */
    function addUser($username, $password, $additional='')
    {
        if (!($this->pwfile->isLocked())) {
            $this->pwfile->lock();
        }

        if (is_array($additional)) {
            $cvsuser = $additional[cvsuser];
        } else {
            $cvsuser = $additional;
        }

        $retval = $this->pwfile->addUser($username, $password, $cvsuser);
        $this->pwfile->close();

        return($retval);
    }

    // }}}
    // {{{ removeUser()

    /**
     * Remove user from the storage container
     *
     * @param string Username
     */
    function removeUser($username)
    {
        if (!($this->pwfile->isLocked())) {
            $this->pwfile->lock();
        }
        $retval = $this->pwfile->delUser($username);  
        $this->pwfile->close();
        return($retval);
    }

    // }}}

}
?>
