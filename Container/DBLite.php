<?php
//
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// |                                                                      |
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

require_once 'Auth/Container.php';
require_once 'DB.php';

/**
 * A lighter storage driver for fetching login data from a database
 *
 * This driver is derived from the DB storage container but
 * with the user manipulation function removed for smaller file size
 * by the PEAR DB abstraction layer to fetch login data.
 *
 * @author   Martin Jansen <mj@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_DB extends Auth_Container
{

    /**
     * Additional options for the storage container
     * @var array
     */
    var $options = array();

    /**
     * DB object
     * @var object
     */
    var $db = null;
    var $dsn = '';

    /**
     * User that is currently selected from the DB.
     * @var string
     */
    var $activeUser = '';

    // {{{ Constructor

    /**
     * Constructor of the container class
     *
     * Initate connection to the database via PEAR::DB
     *
     * @param  string Connection data or DB object
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_DB($dsn)
    {
        $this->options['table']       = 'auth';
        $this->options['usernamecol'] = 'username';
        $this->options['passwordcol'] = 'password';
        $this->options['dsn']         = '';
        $this->options['db_fields']   = '';
        $this->options['cryptType']   = 'md5';
        $this->options['db_options']  = array();

        if (is_array($dsn)) {
            $this->_parseOptions($dsn);
            if (empty($this->options['dsn'])) {
                PEAR::raiseError('No connection parameters specified!');
            }
        } else {
            $this->options['dsn'] = $dsn;
        }
    }

    /**
     * Connect to database by using the given DSN string
     *
     * @access private
     * @param  string DSN string
     * @return mixed  Object on error, otherwise bool
     */
    function _connect(&$dsn)
    {
        if (is_string($dsn) || is_array($dsn)) {
            $this->db =& DB::connect($dsn, $this->options['db_options']);
        } elseif (get_parent_class($dsn) == "db_common") {
            $this->db =& $dsn;
        } else {
            return PEAR::raiseError("Invalid dsn or db object given");
        }

        if (DB::isError($this->db) || PEAR::isError($this->db)) {
            return PEAR::raiseError($this->db->getMessage(), $this->db->getCode());
        } else {
            return true;
        }
    }

    /**
     * Prepare database connection
     *
     * This function checks if we have already opened a connection to
     * the database. If that's not the case, a new connection is opened.
     *
     * @access private
     * @return mixed True or a DB error object.
     */
    function _prepare() {
        if (!DB::isConnection($this->db)) {
            $res = $this->_connect($this->options['dsn']);
            if (DB::isError($res) || PEAR::isError($res)) {
                return $res;
            }
        }
        return true;
    }

    /**
     * Parse options passed to the container class
     *
     * @access private
     * @param  array
     */
    function _parseOptions($array) {
        foreach ($array as $key => $value) {
            if (isset($this->options[$key])) {
                $this->options[$key] = $value;
            }
        }

        /* Include additional fields if they exist */
        if (!empty($this->options['db_fields'])) {
            if (is_array($this->options['db_fields'])) {
                $this->options['db_fields'] = join($this->options['db_fields'], ', ');
            }
            $this->options['db_fields'] = ', '.$this->options['db_fields'];
        }
    }

    /**
     * Get user information from database
     *
     * This function uses the given username to fetch
     * the corresponding login data from the database
     * table. If an account that matches the passed username
     * and password is found, the function returns true.
     * Otherwise it returns false.
     *
     * @param   string Username
     * @param   string Password
     * @return  mixed  Error object or boolean
     */
    function fetchData($username, $password)
    {
        // Prepare for a database query
        $err = $this->_prepare();
        if ($err !== true) {
            return PEAR::raiseError($err->getMessage(), $err->getCode());
        }

        // Find if db_fields contains a *, if so assume all col are selected
        if (strstr($this->options['db_fields'], '*')) {
            $sql_from = "*";
        }
        else{
            $sql_from = $this->options['usernamecol'] . ", ".$this->options['passwordcol'].$this->options['db_fields'];
        }
        
        $query = "SELECT ".$sql_from.
                " FROM ".$this->options['table'].
                " WHERE ".$this->options['usernamecol']." = '".$this->db->quoteString($username)."'";
        $res = $this->db->getRow($query, null, DB_FETCHMODE_ASSOC);

        if (DB::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->getCode());
        }
        if (!is_array($res)) {
            $this->activeUser = '';
            return false;
        }
        if ($this->verifyPassword(trim($password, "\r\n"),
                                  trim($res[$this->options['passwordcol']], "\r\n"),
                                  $this->options['cryptType'])) {
            // Store additional field values in the session
            foreach ($res as $key => $value) {
                if ($key == $this->options['passwordcol'] ||
                    $key == $this->options['usernamecol']) {
                    continue;
                }
                // Use reference to the auth object if exists
                // This is because the auth session variable can change so a static call to setAuthData does not make sence
                if (is_object($this->_auth_obj)) {
                    $this->_auth_obj->setAuthData($key, $value);
                } else {
                    Auth::setAuthData($key, $value);
                }
            }
            $this->activeUser = $res[$this->options['usernamecol']];
            return true;
        }
        $this->activeUser = $res[$this->options['usernamecol']];
        return false;
    }
}
?>
