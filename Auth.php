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
 * Usage example:
 *   
 *    require_once "Auth/Auth.php";
 *    
 *    // We use a MySQL as storage container in this example
 *    $a = new Auth("DB","mysql://martin:test@localhost/test");
 *    
 *    // Detect, if the user is already logged in. If not, draw the
 *    // login form.
 *    $a->start();
 *
 *    if ($a->getAuth()) {
 *        echo "Welcome user ".$a->getUsername()."!<br />\n";
 *        // output the content of your site, that is only visible
 *        // for users which have been authenticated successfully.
 *    }
 *
 *
 * @author  Martin Jansen <mj@php.net>
 * @package Auth
 * @version $Revision$
 */

require_once "PEAR.php";

define("AUTH_IDLED",       -1);
define("AUTH_EXPIRED",     -2);
define("AUTH_WRONG_LOGIN", -3);
define("AUTH_USER_NOBODY", "nobody");

class Auth
{

    /**
     * Auth lifetime in seconds
     * 
     * If this variable is set to 0, auth never expires
     *
     * @var  integer
     * @see  checkAuth()
     */
    var $expire = 0;

    /**
     * Has the auth session expired?
     *
     * @var   bool
     * @see   checkAuth(), drawLogin()
     */
    var $expired = false;

    /**
     * Maximum time of idleness in seconds
     *
     * The difference to $expire is, that the idletime gets
     * refreshed each time, checkAuth() is called. If this
     * variable is set to 0, idle time is never checked.
     *
     * @var integer
     * @see checkAuth()
     */
    var $idle = 0;

    /**
     * Is the maximum idletime over?
     *
     * @var boolean
     * @see checkAuth(), drawLogin();
     */
    var $idled = false;

    /**
     * Storage object
     *
     * @var object
     * @see Auth(), validateLogin()
     */
    var $storage = "";

    /**
     * Function defined by the user, that creates the login screen
     *
     * @var string
     */
    var $loginFunc = "";

    // {{{ Constructor

    /**
     * Constructor
     *
     * Set up the storage driver.
     *
     * @param string    Type of the storage driver
     * @param mixed     Additional options for the storage driver
     *                  (example: if you are using DB as the storage
     *                   driver, you have to pass the dsn string here)
     *
     * @param string    Name of the function that creates the login form
     * @param bool      Is authentication necessary or not
     */
    function Auth($storageDriver = "DB", $options = "", $loginFunc = "")
    {                
        if ($loginFunc != "" && function_exists($loginFunc)) {            
            $this->loginFunc = $loginFunc;
        }        

        $this->storage = $this->_factory($storageDriver,$options);
    }

    // }}}
    // {{{ _factory

    /**
     * Return a storage driver based on $driver and $options
     *
     * @access private
     * @static
     * @param  string $driver  Type of storage class to return
     * @param  string $options Optional parameters for the storage class
     * @return object Object   Storage object
     */
    function _factory($driver, $options = "")
    {
        $storage_path = "Auth/Container/".$driver.".php";
        $storage_class = "Auth_Container_".$driver;

        require_once $storage_path;

        return new $storage_class($options);
    }

    // }}}
    // {{{ assignData()

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
    function assignData() 
    {
        global $HTTP_POST_VARS;
        
        if ($HTTP_POST_VARS['username'] != "") {
            $this->username = $HTTP_POST_VARS['username'];
        }

        if ($HTTP_POST_VARS['password'] != "") {
            $this->password = $HTTP_POST_VARS['password'];
        }
    }

    // }}}
    // {{{ start()

    /**
     * Start new auth session
     *
     * @access private
     */
    function start() 
    {
        session_start();

        $this->assignData();
        
        if (!$this->checkAuth()) {
            $this->login();
        }
    }

    // }}}
    // {{{ login()

    /**
     * Login function
     *
     * @access private
     */
    function login()
    {

        /**
         * When the user has already entered a username,
         * we have to validate it.
         */
        if ($this->username != "") {
            $login_ok = $this->storage->fetchData($this->username,$this->password);
        }

        /**
         * If the login failed or the user entered not username,
         * output the login screen again.
         */

        if ($this->username != "" && !$login_ok) {
            $this->status = AUTH_WRONG_LOGIN;
        }

        if ($this->username == "" || !$login_ok) {
            $this->drawLogin();
            return;
        }
    }

    // }}}
    // {{{ setExpire()

    /**
     * Set the maximum expire time
     *
     * @access private
     * @param  integer time in seconds
     * @param  bool    add time to current expire time or not 
     */
    function setExpire($time,$add = false) 
    {
        if ($add) {
            $this->expire += $time;
        } else {
            $this->expire = $time;
        }
    }

    // }}}
    // {{{ checkAuth()

    /**
     * Checks if there is a session with valid auth information.
     *
     * @access private
     * @return boolean  Whether or not the user is authenticated.
     */
    function checkAuth() 
    {
        if (isset($GLOBALS['HTTP_SESSION_VARS']['auth'])) {

            /** Check if authentication session is expired */
            if ($this->expire > 0 && 
                ($GLOBALS['HTTP_SESSION_VARS']['auth']['timestamp'] + $this->expire) < time()) {

                $this->logout();
                $this->expired = true;
                $this->status = AUTH_EXPIRED;

                Auth::updateIdle();

                return false;
            }

            /** Check if maximum idle time is reached */
            if ($this->idle > 0 &&
                ($GLOBALS['HTTP_SESSION_VARS']['auth']['idle'] + $this->idle) < time()) {

                $this->logout();
                $this->idled = true;
                $this->status = AUTH_IDLED;

                return false;
            }

            if ($GLOBALS['HTTP_SESSION_VARS']['auth']['registered'] == true &&
                $GLOBALS['HTTP_SESSION_VARS']['auth']['username'] != "") {

                Auth::updateIdle();

                return true;
            }
        }

        return false;
    }

    // }}}
    // {{{ setAuth()

    /**
     * Register variable in a session telling that the user
     * has logged in successfully
     *
     * @param string Username
     */
    function setAuth($username) 
    {
        
        if (!isset($GLOBALS['HTTP_SESSION_VARS']['auth'])) {
            session_register('auth');
        }

        $GLOBALS['auth']               = &$GLOBALS['HTTP_SESSION_VARS']['auth'];
        $GLOBALS['auth']['registered'] = true;
        $GLOBALS['auth']['username']   = $username;
        $GLOBALS['auth']['timestamp']  = time();
        $GLOBALS['auth']['idle']       = time();
    }
    
    // }}}
    // {{{ getAuth()

    /**
     * Has the user been authenticated?
     *
     * @return bool  True if the user is logged in, otherwise false.
     */
    function getAuth() {

        if ($GLOBALS['HTTP_SESSION_VARS']['auth']['registered'] == true) {
            return true;
        } else {
            return false;
        }
    }

    // }}}
    // {{{ drawLogin()

    /**
     * Draw the login form
     *
     * Normally you will use this output in your application,
     * because you can pass a different function name to the
     * constructor. For more information on this, please
     * consult the documentation.
     *
     * @access public
     * @global $HTTP_SERVER_VARS
     * @param  string  Username if already entered
     */
    function drawLogin($username = "")
    {       
        if ($this->loginFunc != "") {            
            call_user_func($this->loginFunc, $username, $this->status);
        } else {
            global $HTTP_SERVER_VARS;
     
            echo "<center>\n";
        
            if ($this->status == AUTH_EXPIRED) {
                echo "<i>Your session expired. Please login again!</i>\n";
            } else if ($this->status == AUTH_IDLED) {
                echo "<i>You have been idle for too long. Please login again!</i>\n";
            } else if ($this->status == AUTH_WRONG_LOGIN) {
                echo "<i>Wrong login data!</i>\n";                
            }            

            echo "<form method=\"post\" action=\"" . $HTTP_SERVER_VARS['PHP_SELF'] . "\">\n";
            echo "<table border=\"0\" cellpadding=\"2\" cellspacing=\"0\">\n";
            echo "<tr>\n";
            echo "    <td colspan=\"2\" bgcolor=\"#eeeeee\"><b>Login:</b></td>\n";
            echo "</tr>\n";
            echo "<tr>\n";
            echo "    <td>Username:</td>\n";
            echo "    <td><input type=\"text\" name=\"username\" value=\"" . $username . "\"></td>\n";
            echo "</tr>\n";
            echo "<tr>\n";
            echo "    <td>Password:</td>\n";
            echo "    <td><input type=\"password\" name=\"password\"></td>\n";
            echo "</tr>\n";
            echo "<tr>\n";
            echo "    <td colspan=\"2\" bgcolor=\"#eeeeee\"><input type=\"submit\"></td>\n";
            echo "</tr>\n";
            echo "</table>\n";
            echo "</form>\n";
            echo "</center>\n\n";
        }        
    }

    // }}}
    // {{{ logout()

    /**
     * Logout function
     *
     * This function clears any auth tokes in the currently
     * active session
     */
    function logout() 
    {
        $this->username = "";
        $this->password = "";

        session_unregister('auth');
    }

    // }}}
    // {{{ updateIdle()

    /**
     * Update the idletime
     */
    function updateIdle() {
        $GLOBALS['auth'] = &$GLOBALS['HTTP_SESSION_VARS']['auth'];
        $GLOBALS['auth']['idle'] = time();
    }

    // }}}
    // {{{ getUsername()

    /**
     * Get the username
     *
     * @return string
     */
    function getUsername()
    {
        return $GLOBALS['HTTP_SESSION_VARS']['auth']['username'];
    }

    // }}}
    // {{{ sessionValidThru()

    /**
     * Returns the time up to the session is valid
     *
     * @return integer
     */    
    function sessionValidThru()
    {
        return ($GLOBALS['HTTP_SESSION_VARS']['auth']['idle'] + $this->idle);
    }

    // }}}
}
?>
