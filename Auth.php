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

 /**
 * PEAR::Auth
 *
 * The PEAR::Auth class provides methods for creating an
 * authentication system using PHP.
 *
 * @author  Martin Jansen <mj@php.net>
 * @package Auth
 * @version 0.1   2001-07-11
 */
class Auth
{

    /**
     * Auth lifetime in seconds
     * 
     * If this variable is set to 0, auth never expires
     *
     * @var  integer
     * @see  check_auth()
     */
    var $expire = 0;

    /**
     * Has the auth session expired?
     *
     * @var   bool
     * @see   check_auth(), draw_login();
     */
    var $expired = false;

    /**
     * Storage object
     *
     * @var object
     * @see Auth(), validate_login()
     */
    var $storage = null;

    /**
     * Hash with information about the user
     * @var array
     */
    var $user_data = array();

    /**
     * Use md5 encryption to protect the password?
     * @var bool
     * @see validate_login()
     */
    var $use_md5 = true;

    /**
     * Constructor
     *
     * Set up the storage driver.
     *
     * @param string    Type of the storage driver
     * @param string    Additinal options for the storage driver
     *                  (example: if you are using DB as the storage
     *                   driver, you have to pass the dsn string here)
     */
    function Auth($storage_driver = "DB",$storage_options = "") 
    {
        $this->storage = $this->factory($storage_driver,$storage_options);
    }

    /**
     * Return a storage driver based on $driver and $options
     *
     * @param  string $driver  Type of storage class to return
     * @param  string $options Optional parameters for the storage class
     * @return object Object   Storage object
     */
    function factory($driver, $options = "")
    {        

        $storage_path = "Auth/Container/".$driver.".php";
        $storage_class = "Auth_Container_".$driver;

        require_once $storage_path;

        return new $storage_class($options);
    }

    /**
     * Start new auth session
     */
    function start() 
    {
        session_start();

        $this->assign_data();

        if (!$this->check_auth()) {
            $this->login();
        }
    }


    /**
     * Assign data from login form to internal values
     *
     * This function takes the values for username and password
     * from $HTTP_POST_VARS and assigns them to internal variables.
     * If you wish to use another source apart from $HTTP_POST_VARS,
     * you have to derive this function.
     *
     * @access public
     * @global $HTTP_POST_VARS
     * @see    Auth
     */
    function assign_data() 
    {
        global $HTTP_POST_VARS;
        
        if ($HTTP_POST_VARS['username'] != "") {
            $this->username = $HTTP_POST_VARS['username'];
        }

        if ($HTTP_POST_VARS['password'] != "") {
            $this->password = $HTTP_POST_VARS['password'];
        }
    }

    /**
     * Validate if login data is ok
     *
     * This function fetches the login data from the storage
     * container and compares it to the values of $this->username
     * and $this->password.
     * Note: Because of security reasons, we use md5-encryption
     *       for the passwords by default. If you dont' want to
     *       use md5, set $this->use_md5 on false.
     *
     * @see      login
     * @return   bool
     */
    function validate_login()
    {
        $login_data = $this->storage->fetch_data($this->username);

        $this->user_data = $login_data;

        if ($this->use_md5) {
            $compare_password = md5($this->password);
        } else {
            $compare_password = $this->password;
        }

        if ($login_data['username'] == $this->username && $login_data['password'] == $compare_password) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Login function
     */
    function login()
    {

        /**
         * When the user has already entered a username,
         * we have to validate it.
         */
        if ($this->username != "") {
            $login_ok = $this->validate_login();
        }

        if (!$login_ok) {
            $this->draw_login();
        } else {
            $this->set_auth();
        }

    }

    /**
     * Logout function
     */
    function logout() 
    {
        $this->username = "";
        $this->password = "";

        $GLOBALS['HTTP_SESSION_VARS']['registered'] = false;
        $GLOBALS['HTTP_SESSION_VARS']['username'] = "";
        $GLOBALS['HTTP_SESSION_VARS']['timestamp'] = "";
    }

    /**
     * Set the maximum expire time
     *
     * @access private
     * @param  integer time in seconds
     * @param  bool    add time to current expire time or not 
     */
    function set_expire($time,$add = false) 
    {
        if ($add) {
            $this->expire += $time;
        } else {
            $this->expire = $time;
        }
    }

    /**
     * Checks if there is a session with valid auth information.
     *
     * @return boolean  Whether or not the user is authenticated.
     */
    function check_auth() 
    {
        if (isset($GLOBALS['HTTP_SESSION_VARS']['auth'])) {

            if ($this->expire > 0 && 
                ($GLOBALS['HTTP_SESSION_VARS']['auth']['timestamp'] + $this->expire) < time()) {

                $this->logout();
                $this->expired = true;
                return false;
            }

            if ($GLOBALS['HTTP_SESSION_VARS']['auth']['registered'] == true &&
                $GLOBALS['HTTP_SESSION_VARS']['auth']['username'] != "") {

                return true;
            }
        }

        return false;
    }

    /**
     * Register variable in a session telling that the user has logged in successfully
     */
    function set_auth() 
    {
        
        if (!isset($GLOBALS['HTTP_SESSION_VARS']['auth'])) {
            session_register('auth');
        }

        $GLOBALS['auth'] = &$GLOBALS['HTTP_SESSION_VARS']['auth'];
        $GLOBALS['auth'] = array();
        $GLOBALS['auth']['registered'] = true;
        $GLOBALS['auth']['username'] = $this->username;
        $GLOBALS['auth']['timestamp'] = time();
    }

    /**
     * Draw the login form
     *
     * This function _has_ to be overwritten by the programmer in
     * order to get a proper login form. If you don't overwrite
     * this, it will look terrible :-).
     *
     * @access public
     * @param  string  Username if already entered
     * @param  string  Password if already entered
     */
    function draw_login($username = "", $password = "") 
    {

        echo "<center>\n";
        
        if ($this->expired) {
            echo "<i>Your session expired. Please login again!</i>\n";
        }

        echo "<form method=\"post\" action=\"".$GLOBALS['PHP_SELF']."\">\n";
        echo "<table border=\"0\" cellpadding=\"2\" cellspacing=\"0\">\n";
        echo "<tr>\n";
        echo "    <td colspan=\"2\" bgcolor=\"#eeeeee\"><b>Login:</b></td>\n";
        echo "</tr>\n";
        echo "<tr>\n";
        echo "    <td>Username:</td>\n";
        echo "    <td><input type=\"text\" name=\"username\" value=\"".$username."\"></td>\n";
        echo "</tr>\n";
        echo "<tr>\n";
        echo "    <td>Password:</td>\n";
        echo "    <td><input type=\"password\" name=\"password\" value=\"".$password."\"></td>\n";
        echo "</tr>\n";
        echo "<tr>\n";
        echo "    <td colspan=\"2\" bgcolor=\"#eeeeee\"><input type=\"submit\"></td>\n";
        echo "</tr>\n";
        echo "</table>\n";
        echo "</form>\n";
        echo "</center>\n\n";
        
    }

    /**
     * Get the username
     *
     * @return string
     */
    function get_username()
    {
        return $this->user_data['username'];
    }

    /**
     * Get the password
     *
     * @return string
     */
    function get_password()
    {
        return $this->user_data['password'];
    }


}

// $a = new Auth("DB","mysql://martin:test@localhost/test");

// $a->start();

// echo "<br><br>\n";

// $a->logout();
?>
