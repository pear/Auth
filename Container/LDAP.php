<?php
//
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
// | Authors: Jan Wagner <wagner@netsols.de>                              |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once "Auth/Container.php";
require_once "PEAR.php";

/**
 * Storage driver for fetching login data from LDAP
 *
 * This class is heavily based on the DB and File containers. By default it
 * connects to localhost:389 and searches for uid=$username with the scope
 * "sub". If no search base is specified, it will try to determine it via
 * the namingContexts attribute. It takes its parameters in a hash, connects
 * to the ldap server, binds anonymously, searches for the user, and tries
 * to bind as the user with the supplied password. When a group was set, it
 * will look for group membership of the authenticated user. If all goes
 * well the authentication was successful.
 *
 * Parameters:
 *
 * host:        localhost (default), ldap.netsols.de or 127.0.0.1
 * port:        389 (default) or 636 or whereever your server runs
 * url:         ldap://localhost:389/
 *              useful for ldaps://, works only with openldap2 ?
 *              it will be preferred over host and port
 * scope:       one, sub (default), or base
 * basedn:      the base dn of your server
 * userdn:      gets prepended to basedn when searching for user
 * userattr:    the user attribute to search for (default: uid)
 * useroc:      objectclass of user (for the search filter)
 *              (default: posixAccount)
 * groupdn:     gets prepended to basedn when searching for group
 * groupattr  : the group attribute to search for (default: cn)
 * groupoc    : objectclass of group (for the search filter)
 *              (default: groupOfUniqueNames)
 * memberattr : the attribute of the group object where the user dn
 *              may be found (default: uniqueMember)
 * memberisdn:  whether the memberattr is the dn of the user (default)
 *              or the value of userattr (usually uid)
 * group:       the name of group to search for
 *
 * To use this storage container, you have to use the following syntax:
 *
 * <?php
 * ...
 *
 * $a = new Auth("LDAP", array(
 *       'host' => 'localhost',
 *       'port' => '389',
 *       'basedn' => 'o=netsols,c=de',
 *       'userattr' => 'uid'
 *       );
 *
 * $a2 = new Auth('LDAP', array(
 *       'url' => 'ldaps://ldap.netsols.de',
 *       'basedn' => 'o=netsols,c=de',
 *       'scope' => 'one',
 *       'userdn' => 'ou=People',
 *       'groupdn' => 'ou=Groups',
 *       'groupoc' => 'posixGroup',
 *       'memberattr' => 'memberUid',
 *       'memberisdn' => false,
 *       'group' => 'admin'
 *       );
 *
 * The parameter values have to correspond
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
    var $conn_id = false;

    /**
     * LDAP search function to use
     * @var string
     */
    var $ldap_search_func;

    /**
     * Constructor of the container class
     *
     * @param  $params, associative hash with host,port,basedn and userattr key
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_LDAP($params)
    {
        $this->_setDefaults();

        if (is_array($params)) {
            $this->_parseOptions($params);
        }

        $this->_connect();

        // if basedn is not specified, try to find it via namingContexts
        if ($this->options['basedn'] == "") {           
            $result_id = @ldap_read($this->conn_id, "", "(objectclass=*)", array("namingContexts"));

            if (ldap_count_entries($this->conn_id, $result_id) == 1) {
                $entry_id = ldap_first_entry($this->conn_id, $result_id);
                $attrs = ldap_get_attributes($this->conn_id, $entry_id);
                $basedn = $attrs['namingContexts'][0];

                if ($basedn != "") {
                    $this->options['basedn'] = $basedn;
                }
            }
            ldap_free_result($result_id);
        }

        // if base ist still not set, raise error
        if ($this->options['basedn'] == "") {
            return PEAR::raiseError("Auth_Container_LDAP: LDAP search base not specified!", 41, PEAR_ERROR_DIE);
        }

        return true;
    }

    // }}}
    // {{{ _connect()

    /**
     * Connect to the LDAP server using the global options
     *
     * @access private
     * @return object  Returns a PEAR error object if an error occurs.
     */
    function _connect()
    {
        // connect
        if (isset($this->options['url']) && $this->options['url'] != '') {
            $this->conn_id = @ldap_connect($this->options['url']);
        } else {
            $this->conn_id = @ldap_connect($this->options['host'], $this->options['port']);
            
        }

        // try switchig to LDAPv3
        $ver = 0;
        if(@ldap_get_option($this->conn_id, LDAP_OPT_PROTOCOL_VERSION, $ver) && $ver >= 2) {
            @ldap_set_option($this->conn_id, LDAP_OPT_PROTOCOL_VERSION, 3);
        }

        // bind anonymously for searching
        if ((@ldap_bind($this->conn_id)) == false) {
            return PEAR::raiseError("Auth_Container_LDAP: Could not connect and bind to LDAP server.", 41, PEAR_ERROR_DIE);
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
        $this->options['host']        = 'localhost';
        $this->options['port']        = '389';
        $this->options['scope']       = 'sub';
        $this->options['basedn']      = '';
        $this->options['userdn']      = '';
        $this->options['userattr']    = "uid";
        $this->options['useroc']      = 'posixAccount';
        $this->options['groupdn']     = '';
        $this->options['groupattr']   = 'cn';
        $this->options['groupoc']     = 'groupOfUniqueNames';
        $this->options['memberattr']  = 'uniqueMember';
        $this->options['memberisdn']  = true;
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

        // get the according search function for selected scope
        switch($this->options['scope']) {
        case 'one':
            $this->ldap_search_func = 'ldap_list';
            break;
        case 'base':
            $this->ldap_search_func = 'ldap_read';
            break;
        default:
            $this->ldap_search_func = 'ldap_search';
            break;
        }
    }

    /**
     * Fetch data from LDAP server
     *
     * Searches the LDAP server for the given username/password
     * combination.
     *
     * @param  string Username
     * @param  string Password
     * @return boolean
     */
    function fetchData($username, $password)
    {        
        // make search filter
        $filter = sprintf('(&(objectClass=%s)(%s=%s))', $this->options['useroc'], $this->options['userattr'], $username);

        // make search base dn
        $search_basedn = $this->options['userdn'];
        if ($search_basedn != '' && substr($search_basedn, -1) != ',') {
            $search_basedn .= ',';
        }
        $search_basedn .= $this->options['basedn'];
        
        // make functions params array
        $func_params = array($this->conn_id, $search_basedn, $filter, array($this->options['userattr']));

        // search
        if (($result_id = @call_user_func_array($this->ldap_search_func, $func_params)) == false) {
            return false;
        }

        // did we get just one entry?
        if (ldap_count_entries($this->conn_id, $result_id) == 1) {

            // then get the user dn
            $entry_id = ldap_first_entry($this->conn_id, $result_id);
            $user_dn  = ldap_get_dn($this->conn_id, $entry_id);
            $attrval  = ldap_get_values($this->conn_id, $entry_id, $this->options['userattr']);

            ldap_free_result($result_id);

            // need to catch an empty password as openldap seems to return TRUE
            // if anonymous binding is allowed
            if ($password != "") {

                // try binding as this user with the supplied password
                if (@ldap_bind($this->conn_id, $user_dn, $password)) {

                    // check group if appropiate
                    if(isset($this->options['group'])) {
                        // decide whether memberattr value is a dn or the unique useer attribute (uid)
                        return $this->checkGroup(($this->options['memberisdn']) ? $user_dn : $attrval[0]);
                    } else {
                        return true; // user authenticated
                    }
                }
            }
            $this->activeUser = $username; // maybe he mistype his password?
        }
        // default
        return false;
    }

    /**
     * Validate group membership
     *
     * Searches the LDAP server for group membership of the
     * authenticated user
     *
     * @param  string Distinguished Name of the authenticated User
     * @return boolean
     */
    function checkGroup($user) 
    {
        // make filter
        $filter = sprintf('(&(%s=%s)(objectClass=%s)(%s=%s))',
                          $this->options['groupattr'],
                          $this->options['group'],
                          $this->options['groupoc'],
                          $this->options['memberattr'],
                          $user
                          );

        // make search base dn
        $search_basedn = $this->options['groupdn'];
        if($search_basedn != '' && substr($search_basedn, -1) != ',') {
            $search_basedn .= ',';
        }
        $search_basedn .= $this->options['basedn'];
        
        $func_params = array($this->conn_id, $search_basedn, $filter, array($this->options['memberattr']));
        
        // search
        if(($result_id = @call_user_func_array($this->ldap_search_func, $func_params)) == false) {
            return false;
        }

        if(ldap_count_entries($this->conn_id, $result_id) == 1) {
            ldap_free_result($result_id);
            return true;
        }

        // default
        return false;
    }
}

?>
