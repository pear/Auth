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

require_once "Auth/Container.php";
require_once "DB.php";

/**
 * Storage driver for fetching login data from a database
 *
 * This storage driver can use all databases which are supported
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

    /**
     * User that is currently selected from the DB.
     * @var string
     */
    var $activeUser = "";

    // {{{ Constructor

    /**
     * Constructor of the container class
     *
     * Initate connection to the database via PEAR::DB
     *
     * @param  $dsn   string connection data or DB object
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_DB($dsn)
    {
        $this->_setDefaults();

        if (is_array($dsn)) {

            $this->_parseOptions($dsn);

            if ($this->options['dsn'] != "") {
                $this->_connect($this->options['dsn']);
                return true;
            } else {
                return new DB_Error("No connection parameters specified!");
            }
        }

        $this->_connect($dsn);
    }

    // }}}
    // {{{ _connect()

    /**
     * Connect to database by using the given DSN string
     *
     * @access private
     * @param  string DSN string
     * @return mixed  Object on error, otherwise bool
     */
    function _connect($dsn)
    {
        if (is_string($dsn)) {
            $this->db = DB::Connect($dsn);
        } elseif (get_parent_class($dsn) == "db_common") {
            $this->db = $dsn;
        } elseif (is_object($dsn) && DB::isError($dsn)) {
            return new DB_Error($dsn->code, PEAR_ERROR_DIE);
        } else {
            return new PEAR_Error("The given dsn was not valid in file " . __FILE__ . " at line " . __LINE__,
                                  41,
                                  PEAR_ERROR_RETURN,
                                  null,
                                  null
                                  );

        }

        if (DB::isError($this->db)) {
            return new DB_Error($this->db->code, PEAR_ERROR_DIE);
        } else {
            return true;
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
        $this->options['table']       = "auth";
        $this->options['usernamecol'] = "username";
        $this->options['passwordcol'] = "password";
        $this->options['dsn']         = "";
        $this->options['db_fields']   = "*";
        $this->options['cryptType']   = "md5";
    }

    // }}}
    // {{{ _parseOptions()

    /**
     * Parse options passed to the container class
     *
     * @access private
     * @param  array
     */
    function _parseOptions($array)
    {
        foreach ($array as $key => $value) {
            if (isset($this->options[$key])) {
                $this->options[$key] = $value;
            }
        }
    }

    // }}}
    // {{{ fetchData()

    /**
     * Get user information from database
     *
     * This function uses the given username to fetch
     * the corresponding login data from the database
     * table. If an account that matches the passed username
     * and password is found, the function return true. 
     * Otherwise it returns false.
     *
     * @param   string Username
     * @param   string Password
     * @return  mixed  Error object or boolean
     */
    function fetchData($username, $password)
    {
        /* Include additional fields if they exist */
        if ($this->options["db_fields"] != "*") {
            $cols = "," . $this->options["db_fields"];
        } else {
            $cols = "";
        }

        $query = sprintf("SELECT %s FROM %s
                             WHERE %s = '%s'",
                         $this->options['usernamecol'] . ", "
                         . $this->options['passwordcol']
                         . $cols,
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->db->quoteString($username)
                         );

        $res = $this->db->query($query);

        if (DB::isError($res)) {
            return new DB_Error($res->code, PEAR_ERROR_DIE);
        } else {
            $entry = $res->fetchRow(DB_FETCHMODE_ASSOC);

            if (is_array($entry)) {
                if ($this->verifyPassword($password, 
                                          $entry[$this->options['passwordcol']],
                                          $this->options['cryptType']))
                {
                    Auth::setAuth($entry[$this->options['usernamecol']]);
                    $res->free();

                    return true;
                } else {
                    $this->activeUser = $entry[$this->options['usernamecol']];
                    return false;
                }
            } else {
                $this->activeUser = "";
                return false;
            }
        }
    }

    // }}}
    // {{{ listUsers()

    function listUsers()
    {
        $retVal = array();

        $query = sprintf("SELECT %s FROM %s",
                         $this->options['db_fields'],
                         $this->options['table']
                         );

        $res = $this->db->query($query);

        if (DB::isError($res)) {
            return new DB_Error($res->code, PEAR_ERROR_DIE);
        } else {
            while ($row = $res->fetchRow(DB_FETCHMODE_ASSOC)) {
                $retVal[] = $row;
            }
        }

        return $retVal;
    }

    // }}}
    // {{{ addUser()

    /**
     * Add user to the storage container
     *
     * @access public
     * @param  string Username
     * @param  string Password
     * @param  mixed  Additional information that are stored in the DB
     *
     * @return mixed True on success, otherwise error object
     */
    function addUser($username, $password, $additional = "")
    {
        if (function_exists($this->options['cryptType'])) {
            $cryptFunction = $this->options['cryptType'];
        } else {
            $cryptFunction = "md5";
        }

        $additional_key = "";
        $additional_value = "";

        if (is_array($additional)) {
            foreach ($additional as $key => $value) {
                $additional_key .= ", " . $key;
                $additional_value .= ", '" . $value . "'";
            }
        }

        $query = sprintf("INSERT INTO %s (%s, %s%s) VALUES ('%s', '%s'%s)",
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->options['passwordcol'],
                         $additional_key,
                         $username,
                         $cryptFunction($password),
                         $additional_value
                         );

        $res = $this->db->query($query);

        if (DB::isError($res)) {
           return new DB_Error($res->code, PEAR_ERROR_DIE);
        } else {
          return true;
        }
    }

    // }}}
    // {{{ removeUser()

    /**
     * Remove user from the storage container
     *
     * @access public
     * @param  string Username
     *
     * @return mixed True on success, otherwise error object
     */
    function removeUser($username)
    {
        $query = sprintf("DELETE FROM %s WHERE %s = '%s'",
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $username
                         );

        $res = $this->db->query($query);

        if (DB::isError($res)) {
           return new DB_Error($res->code, PEAR_ERROR_DIE);
        } else {
          return true;
        }
    }

    // }}}
}
?>
