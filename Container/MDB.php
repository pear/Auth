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
// | Author: Lorenzo Alberton <l.alberton@quipo.it>                                  |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once 'Auth/Container/DB.php';
require_once 'MDB.php';

/**
 * Storage driver for fetching login data from a database
 *
 * This storage driver can use all databases which are supported
 * by the PEAR MDB abstraction layer to fetch login data.
 *
 * @author   Lorenzo Alberton <l.alberton@quipo.it>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_MDB extends Auth_Container_DB
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
    function Auth_Container_MDB($dsn)
    {
        $this->_setDefaults();

        if (is_array($dsn)) {
            $this->_parseOptions($dsn);

            if (empty($this->options['dsn'])) {
                PEAR::raiseError('No connection parameters specified!');
            }
        } else {
            $this->options['dsn'] = $dsn;
        }
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
        if (is_string($dsn) || is_array($dsn)) {
            $this->db =& MDB::Connect($dsn);
        } elseif (get_parent_class($dsn) == "mdb_common") {
            $this->db = $dsn;
        } elseif (is_object($dsn) && MDB::isError($dsn)) {
            return PEAR::raiseError("", $dsn->code, PEAR_ERROR_DIE);
        } else {
            return PEAR::raiseError('The given dsn was not valid in file ' . __FILE__ . ' at line ' . __LINE__,
                                    41,
                                    PEAR_ERROR_RETURN,
                                    null,
                                    null
                                    );

        }

        if (MDB::isError($this->db)) {
            return PEAR::raiseError("", $this->db->code, PEAR_ERROR_DIE);
        } else {
            return true;
        }
    }

    // }}}
    // {{{ query()

    /**
     * Prepare query to the database
     *
     * This function checks if we have already opened a connection to
     * the database. If that's not the case, a new connection is opened.
     * After that the query is passed to the database.
     *
     * @access public
     * @param  string Query string
     * @return True or DB_Error
     */
    function query($query)
    {
        if($this->db === null) {
            $this->_connect($this->options['dsn']);
        }
        /*
        if (!MDB::isConnection($this->db)) {
            $this->_connect($this->options['dsn']);
        }
        */
        return $this->db->query($query);
    }

    // }}}
    // {{{ fetchData()

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
        /* Include additional fields if they exist */
        if ($this->options['db_fields'] != '*') {
            $cols = ',' . $this->options['db_fields'];
        } else {
            $cols = '';
        }

        $query = sprintf("SELECT %s FROM %s
                             WHERE %s = %s",
                         $this->options['usernamecol'] . ', '
                         . $this->options['passwordcol']
                         . $cols,
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->db->getTextValue($username)
                         );

        $res = $this->query($query);

        if (MDB::isError($res)) {
            return PEAR::raiseError('', $res->code, PEAR_ERROR_DIE);
        } else {
            $entry = $this->db->fetchRow($res, MDB_FETCHMODE_ASSOC);

            if (is_array($entry)) {
                if ($this->verifyPassword($password, 
                                          $entry[$this->options['passwordcol']],
                                          $this->options['cryptType']))
                {
                    return true;
                } else {
                    $this->activeUser = $entry[$this->options['usernamecol']];
                    return false;
                }
            } else {
                $this->activeUser = '';
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

        $res = $this->query($query);

        if (MDB::isError($res)) {
            return PEAR::raiseError("", $res->code, PEAR_ERROR_DIE);
        } else {
            while ($row = $this->db->fetchRow($res, MDB_FETCHMODE_ASSOC)) {
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
            $cryptFunction = 'md5';
        }

        $additional_key = '';
        $additional_value = '';

        if (is_array($additional)) {
            foreach ($additional as $key => $value) {
                $additional_key .= ', ' . $key;
                $additional_value .= ", " . $this->db->getTextValue($value);
            }
        }

        $query = sprintf("INSERT INTO %s (%s, %s%s) VALUES (%s, %s%s)",
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->options['passwordcol'],
                         $additional_key,
                         $this->db->getTextValue($username),
                         $this->db->getTextValue($cryptFunction($password)),
                         $additional_value
                         );

        $res = $this->query($query);

        if (MDB::isError($res)) {
           return PEAR::raiseError("", $res->code, PEAR_ERROR_DIE);
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
        $query = sprintf("DELETE FROM %s WHERE %s = %s",
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->db->getTextValue($username)
                         );

        $res = $this->query($query);

        if (MDB::isError($res)) {
           return PEAR::raiseError("", $res->code, PEAR_ERROR_DIE);
        } else {
          return true;
        }
    }

    // }}}
}
?>
