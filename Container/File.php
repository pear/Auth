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
 * This storage container can handle CVS pserver style passwd files.
 *
 * @author   Stefan Ekman <stekman@sedata.org>
 * @author   Michael Wallner <mike@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_File extends Auth_Container
{
    /**
     * Path to passwd file
     * 
     * @var string
     */
    var $pwfile = '';

    // {{{ Constructor

    /**
     * Constructor of the container class
     *
     * @param  string $filename             path to passwd file
     * @return object Auth_Container_File   new Auth_Container_File object
     */
    function Auth_Container_File($filename)
    {
        $this->pwfile = $filename;
    }

    // }}}
    // {{{ fetchData()

    /**
     * Authenticate an user
     *
     * @param   string  username
     * @param   string  password
     * @return  mixed   boolean|PEAR_Error
     */
    function fetchData($user, $pass)
    {
        return File_Passwd::staticAuth('Cvs', $this->pwfile, $user, $pass);
    }

    // }}}
    // {{{ listUsers()
    
    function listUsers()
    {
        $pw_obj = &$this->_load();
        if (PEAR::isError($pw_obj)) {
            return array();
        }

        $users  = $pw_obj->listUser();
        if (!is_array($users)) {
            return array();
        }

        foreach ($users as $key => $value) {
            $retVal[] = array("username" => $key, 
                              "password" => $value['passwd'],
                              "cvsuser"  => $value['system']);
        }

        return $retVal;
    }

    // }}}

    /**
     * Add a new user to the storage container
     *
     * @param string username
     * @param string password
     * @param mixed  CVS username
     *
     * @return boolean
     */
    function addUser($user, $pass, $additional='')
    {
        $cvs =  is_array($additional) ? $additional['cvsuser'] : $additional;

        $pw_obj = &$this->_load();
        if (PEAR::isError($pw_obj)) {
            return false;
        }

        
        $res = $pw_obj->addUser($user, $pass, $cvs);
        if(PEAR::isError($res)){
            return(false);
        }
        $pw_obj->save();
        return($res);
    }

    // }}}
    // {{{ removeUser()

    /**
     * Remove user from the storage container
     *
     * @param string Username
     */
    function removeUser($user)
    {
        $pw_obj = &$this->_load();
        if (PEAR::isError($pw_obj)) {
            return false;
        }
        
        
        $res = $pw_obj->delUser($user);
        if(PEAR::isError($res)){
            return(false);
        }
        $pw_obj->save();
        return(true);
    }

    // }}}
    // {{{ _load()
    
    function &_load()
    {
        static $pw_obj;
        if (!isset($pw_obj)) {
            $pw_obj = File_Passwd::factory('Cvs');
            $pw_obj->setFile($this->pwfile);
        }
        return $pw_obj;
    }

}
?>
