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
 */
class Auth_Container_DB extends Auth_Container
{
        
    /**
     * Name of the database table
     * @var string
     * @see fetch_data
     */
    var $table = "auth";

    /**
     * Name of the column where the username is stored
     * @var string
     * @see fetch_data
     */
    var $username_col = "username";

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

        if (is_string($dsn)) {

            $this->db = DB::Connect($dsn);

            if (DB::isError($db)) {
                return new DB_Error($db->code,PEAR_ERROR_DIE);
            }

        }

        elseif (is_object($dsn) && DB::isError($dsn)) {
            echo "The given param was not valid in file ".__FILE__." at line ".__LINE__."<br>\n";
            return new DB_Error($dsn->code,PEAR_ERROR_DIE);
        }

        // if parent class is db_common, then it's already a connected identifier
        elseif (get_parent_class($dsn) == "db_common") {
            $this->db = $dsn;
        }

        else {
            return new PEAR_Error("The given dsn (".$dsn.") was not valid in file ".__FILE__." at line ".__LINE__,41,PEAR_ERROR_RETURN,null,null);
        }
    }

    /**
     * Get user information from database
     *
     * This function uses the given username to fetch
     * the corresponding login data from the database
     * table. This function returns a associative hash
     * that contains the values for all fields in the
     * table.
     *
     * @param   string Username
     * @return  array  Hash with database information for $username
     */
    function fetch_data($username) 
    {
        
        $query = sprintf("SELECT * FROM %s WHERE %s = '%s'",
                         $this->table,
                         $this->username_col,
                         $username
                         );
        
        $res = $this->db->query($query);
        
        if (DB::isError($res)) {
            return new DB_Error($dsn->code,PEAR_ERROR_DIE);
        } else {
            $entry = $res->FetchRow(DB_FETCHMODE_ASSOC);
         
            return $entry;
        }    
    }
}
?>
