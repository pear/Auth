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
// | Author: Lorenzo Alberton <l.alberton@quipo.it>                       |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once 'Auth/Container.php';
require_once 'MDB2.php';

/**
 * Storage driver for fetching login data from a database
 *
 * This storage driver can use all databases which are supported
 * by the PEAR MDB2 abstraction layer to fetch login data.
 *
 * @author   Lorenzo Alberton <l.alberton@quipo.it>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_MDB2 extends Auth_Container
{

    /**
     * Additional options for the storage container
     * @var array
     */
    var $options = array();

    /**
     * MDB object
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
     * Initate connection to the database via PEAR::MDB2
     *
     * @param  string Connection data or MDB2 object
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_MDB2($dsn)
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
     * @param  mixed DSN string | array | mdb object
     * @return mixed  Object on error, otherwise bool
     */
    function _connect($dsn)
    {
        if (is_string($dsn) || is_array($dsn)) {
            $this->db =& MDB2::connect($dsn, $this->options['db_options']);
        } elseif (is_subclass_of($dsn, 'MDB2_Driver_Common')) {
            $this->db = $dsn;
        } elseif (is_object($dsn) && MDB2::isError($dsn)) {
            return PEAR::raiseError($dsn->getMessage(), $dsn->code);
        } else {
            return PEAR::raiseError('The given dsn was not valid in file ' . __FILE__ . ' at line ' . __LINE__,
                                    41,
                                    PEAR_ERROR_RETURN,
                                    null,
                                    null
                                    );

        }

        if (MDB2::isError($this->db) || PEAR::isError($this->db)) {
            return PEAR::raiseError($this->db->getMessage(), $this->db->code);
        }
        return true;
    }

    // }}}
    // {{{ _prepare()

    /**
     * Prepare database connection
     *
     * This function checks if we have already opened a connection to
     * the database. If that's not the case, a new connection is opened.
     *
     * @access private
     * @return mixed True or a MDB error object.
     */
    function _prepare()
    {
        if (is_subclass_of($this->db, 'MDB2_Driver_Common')) {
            return true;
        }
        return $this->_connect($this->options['dsn']);
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
     * @return mixed  a MDB_result object or MDB_OK on success, a MDB
     *                or PEAR error on failure
     */
    function query($query)
    {
        $err = $this->_prepare();
        if ($err !== true) {
            return $err;
        }
        return $this->db->exec($query);
    }

    // }}}
    // {{{ _setDefaults()

    /**
     * Set some default options
     *
     * @access private
     * @return void
     */
    function _setDefaults()
    {
        $this->options['table']       = 'auth';
        $this->options['usernamecol'] = 'username';
        $this->options['passwordcol'] = 'password';
        $this->options['dsn']         = '';
        $this->options['db_fields']   = '';
        $this->options['cryptType']   = 'md5';
        $this->options['db_options']  = array();
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

        // Include additional fields if they exist
        if (!empty($this->options['db_fields'])) {
            if (is_array($this->options['db_fields'])) {
                $this->options['db_fields'] = join($this->options['db_fields'], ', ');
            }
            $this->options['db_fields'] = ', ' . $this->options['db_fields'];
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
     * and password is found, the function returns true.
     * Otherwise it returns false.
     *
     * @param   string Username
     * @param   string Password
     * @param   boolean If true password is secured using a md5 hash
     *                  the frontend and auth are responsible for making sure the container supports
     *                  challenge response password authentication
     * @return  mixed  Error object or boolean
     */
    function fetchData($username, $password, $isChallengeResponse=false)
    {
        // Prepare for a database query
        $err = $this->_prepare();
        if ($err !== true) {
            return PEAR::raiseError($err->getMessage(), $err->getCode());
        }

        //Check if db_fields contains a *, if so assume all columns are selected
        if (strstr($this->options['db_fields'], '*')) {
            $sql_from = '*';
        } else {
            $sql_from = $this->options['usernamecol'] . ', '. $this->options['passwordcol'] . $this->options['db_fields'];
        }
        $query = sprintf("SELECT %s FROM %s WHERE %s = %s",
                         $sql_from,
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->db->quote($username, 'text')
                         );

        $res = $this->db->queryRow($query, null, MDB2_FETCHMODE_ASSOC);
        if (MDB2::isError($res) || PEAR::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->getCode());
        }
        if (!is_array($res)) {
            $this->activeUser = '';
            return false;
        }

        // Perform trimming here before the hashing
        $password = trim($password, "\r\n");
        $res[$this->options['passwordcol']] = trim($res[$this->options['passwordcol']], "\r\n");
        // If using Challenge Response md5 the pass with the secret
        if ($isChallengeResponse) {
            $res[$this->options['passwordcol']] =
                md5($res[$this->options['passwordcol']].$this->_auth_obj->session['loginchallenege']);
            // UGLY cannot avoid without modifying verifyPassword
            if ($this->options['cryptType'] == 'md5') {
                $res[$this->options['passwordcol']] = md5($res[$this->options['passwordcol']]);
            }
        }
        if ($this->verifyPassword($password,
                                  $res[$this->options['passwordcol']],
                                  $this->options['cryptType'])) {
            // Store additional field values in the session
            foreach ($res as $key => $value) {
                if ($key == $this->options['passwordcol'] ||
                    $key == $this->options['usernamecol']) {
                    continue;
                }
                // Use reference to the auth object if exists
                // This is because the auth session variable can change so a static call to setAuthData does not make sense
                $this->_auth_obj->setAuthData($key, $value);
            }
            return true;
        }

        $this->activeUser = $res[$this->options['usernamecol']];
        return false;
    }

    // }}}
    // {{{ listUsers()

    /**
     * Returns a list of users from the container
     *
     * @return mixed array|PEAR_Error
     * @access public
     */
    function listUsers()
    {
        $err = $this->_prepare();
        if ($err !== true) {
            return PEAR::raiseError($err->getMessage(), $err->getCode());
        }

        $retVal = array();

        //Check if db_fields contains a *, if so assume all columns are selected
        if (strstr($this->options['db_fields'], '*')) {
            $sql_from = '*';
        } else {
            $sql_from = $this->options['db_fields'];
        }

        $query = sprintf('SELECT %s FROM %s',
                         $sql_from,
                         $this->options['table']
                         );

        $res = $this->db->queryAll($query, null, MDB2_FETCHMODE_ASSOC);
        if (MDB2::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->getCode());
        } else {
            foreach ($res as $user) {
                $user['username'] = $user[$this->options['usernamecol']];
                $retVal[] = $user;
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

        if (isset($this->options['cryptType']) && $this->options['cryptType'] == 'none') {
            $cryptFunction = 'strval';
        } elseif (isset($this->options['cryptType']) && function_exists($this->options['cryptType'])) {
            $cryptFunction = $this->options['cryptType'];
        } else {
            $cryptFunction = 'md5';
        }

        $password = $cryptFunction($password);

        $additional_key   = '';
        $additional_value = '';

        if (is_array($additional)) {
            foreach ($additional as $key => $value) {
                $additional_key   .= ', ' . $key;
                $additional_value .= ', ' . $this->db->quote($value, 'text');
            }
        }

        $query = sprintf("INSERT INTO %s (%s, %s%s) VALUES (%s, %s%s)",
                         $this->options['table'],
                         $this->options['usernamecol'],
                         $this->options['passwordcol'],
                         $additional_key,
                         $this->db->quote($username, 'text'),
                         $this->db->quote($password, 'text'),
                         $additional_value
                         );

        $res = $this->query($query);

        if (MDB2::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->code);
        }
        return true;
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
                         $this->db->quote($username, 'text')
                         );

        $res = $this->query($query);

        if (MDB2::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->code);
        }
        return true;
    }

    // }}}
    // {{{ changePassword()

    /**
     * Change password for user in the storage container
     *
     * @param string Username
     * @param string The new password (plain text)
     */
    function changePassword($username, $password)
    {
        if (isset($this->options['cryptType']) && $this->options['cryptType'] == 'none') {
            $cryptFunction = 'strval';
        } elseif (isset($this->options['cryptType']) && function_exists($this->options['cryptType'])) {
            $cryptFunction = $this->options['cryptType'];
        } else {
            $cryptFunction = 'md5';
        }

        $password = $cryptFunction($password);

        $query = sprintf("UPDATE %s SET %s = %s WHERE %s = %s",
                         $this->options['table'],
                         $this->options['passwordcol'],
                         $this->db->quote($password, 'text'),
                         $this->options['usernamecol'],
                         $this->db->quote($username, 'text')
                         );

        $res = $this->query($query);

        if (MDB2::isError($res)) {
            return PEAR::raiseError($res->getMessage(), $res->code);
        }
        return true;
    }

    // }}}
    // {{{ supportsChallengeResponse()

    /**
     * Determine if this container supports
     * password authentication with challenge response
     *
     * @return bool
     * @access public
     */
    function supportsChallengeResponse()
    {
        return in_array($this->options['cryptType'], array('md5', 'none', ''));
    }

    // }}}
    // {{{ getCryptType()

    /**
     * Returns the selected crypt type for this container
     *
     * @return string Function used to crypt the password
     */
    function getCryptType()
    {
        return $this->options['cryptType'];
    }

    // }}}

}
?>