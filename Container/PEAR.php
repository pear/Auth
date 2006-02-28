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

/** Include PEAR XML_RPC */
require_once('XML/RPC.php');

/**
 * Storage driver for authenticating against PEAR website
 *
 * This driver provides a method for authenticating against the pear.php.net
 * authentication system.
 *
 * @author   Yavor Shahpasov <yavo@netsmart.com.cy>
 * @author   Adam Ashley <aashley@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_Pear
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
        $rpc = new XML_RPC_Client('/xmlrpc.php', 'pear.php.net');
        $rpc_message = new XML_RPC_Message("user.info", array(new XML_RPC_Value($username, "string")) );
        
        // Error Checking howto ???
        $result = $rpc->send($rpc_message);
        $value = $result->value();
        $userinfo = xml_rpc_decode($value);
        if ($userinfo['password'] == md5($password)) {
            $this->activeUser = $userinfo['handle'];
            foreach ($userinfo as $uk=>$uv) {
                $this->_auth_obj->setAuthData($uk, $uv);
            }
            return true;
        }
        return false;
    }

    // }}}
    
}
?>
