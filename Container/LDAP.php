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
// | Authors: Jan Wagner <wagner@netsols.de>                              |
// |          Martin Jansen <mj@php.net>                                  |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once "Auth/Container.php";
require_once "PEAR.php";

/**
 * Storage driver for fetching login data from LDAP
 *
 * This class is heavily based on the DB and File containers.
 * It takes four parameters (host,port,base and userattr),
 * from which only base as the ldap search base is required
 * if your server runs on localhost:389 and the user-
 * attribute is uid (i.e. dn: uid=wagner,o=netsols,c=de).
 * in a associative hash, connects to the ldap server,
 * binds anonymously, searches for the user, and tries to
 * bind as the user with the supplied password. If all
 * goes well the authentication was successful.
 *
 * To use this storage containers, you have to use the
 * following syntax:
 *
 * <?php
 * ...
 *
 * $a = new Auth("LDAP", array(
 *       'host' => 'localhost',
 *       'port' => '389';
 *       'base' => 'o=netsols,c=de',
 *       'userattr' => 'uid'
 *       );
 *
 * The values for host, port and base have to correspond
 * to the ones for your LDAP server of course.
 *
 * @author   Jan Wagner <wagner@netsols.de>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_LDAP extends Auth_Container
{
    /**
     * Options for the class
     * @var array
     */
    var $options = array();

    /**
     * Connection ID of LDAP
     * @var string
     */
    var $conn_id = 0;

    /**
     * Constructor of the container class
     *
     * @param  $params, associative hash with host,port,base and userattr key
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_Ldap($params)
    {
        $this->_setDefaults();

        if (is_array($params)) {

            $this->_parseOptions($params);

            if ($this->options['base'] != "") {
                $this->_connect();
                return true;
            } else {
                return new Pear_Error("No LDAP Search Base specified!", 41, PEAR_ERROR_DIE);
            }        
        }

        return new Pear_Error("No parameters specified", 41, PEAR_ERROR_DIE);
    }

    // }}}
    // {{{ _connect()

    /**
     * Connect to the LDAP server using the global options
     *
     * @access private
     * @return mixed  Object on error, otherwise bool
     */
    function _connect()
    {
        // connect
		if (($this->conn_id = @ldap_connect($this->options['host'], $this->options['port'])) == false) {
			return new PEAR_Error("Error connecting to LDAP.", 41, PEAR_ERROR_DIE);
		}
        // bind anonymously for searching
		if ((@ldap_bind($this->conn_id)) == false) {
            return new PEAR_Error("Error binding anonymously to LDAP.", 41, PEAR_ERROR_DIE);
		}
    }

    // }}}
    // {{{ _setDefaults()

    /**
     * Set some default options
     *
     * @access private
     */
    function _setDefaults()
    {
        $this->options['host']     = 'localhost';
        $this->options['port']     = '389';
        $this->options['base']     = '';
        $this->options['userattr'] = "uid";
    }

    /**
     * Parse options passed to the container class
     *
     * @access private
     * @param  array
     */
    function _parseOptions($array)
    {
        foreach ($array as $key => $value) {
            $this->options[$key] = $value;
        }
    }

    function fetchData($username, $password)
    {
        // search
        if (($result_id = @ldap_search($this->conn_id,$this->options['basedn'],$this->options['userattr']."=".$username)) == false) {
            return new PEAR_Error("Error searching LDAP.", 41, PEAR_ERROR_DIE);
        }
        // did we get just one entry?
        if (ldap_count_entries($this->conn_id, $result_id) == 1) {

            // then get the user dn
            $entry_id = ldap_first_entry($this->conn_id, $result_id);
            $user_dn = ldap_get_dn($this->conn_id, $entry_id);

            // and try binding as this user with the supplied password
            if (@ldap_bind($this->conn_id, $user_dn, $password)) {
                // auth successful
                Auth::setAuth($username);
                return true;
            }
        }
        // default
        return false;
    }
}
?>
