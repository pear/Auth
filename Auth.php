<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
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
 * The constructor accepts these parameters:
 *
 *   Auth( string $storageDriver, mixed $options, 
 *         string $loginFunction, bool $showLogin )
 *
 *      $storageDriver  : Storage driver for user data 
 *                        (currently only DB is supported)
 *
 *      $options        : Either a valid dsn or an array of this form: 
 *                        array ( 
 *                            'table'         => $table_with_userdata,
 *                            'usernamecol'   => $column_with_username,
 *                            'passwordcol'   => $column_with_md5_pw
 *                        )
 *
 *      $loginFunction  : The name of a user defined function which draws
 *                        the login form (see drawLogin() for an example)
 *                        (optional, ignored if empty)
 *
 *      $showLogin      : Define if the login form should be displayed
 *                        if the user hasn't logged in already.
 *                        (optional, default: true)
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
 * Advanced example:
 *
 *  Set up the Auth class in an auto_prepend file like this:
 *
 *    require_once "Auth/Auth.php";
 *
 *    // define dsn
 *    $dsn = "mysql://martin:test@localhost/test";
 *  
 *    // set options
 *    $options = array(
 *      'table'         => 'myuser',
 *      'username'   => 'userlogin',
 *      'password'   => 'cryptpassword'
 *    );
 *
 *    // define login form function
 *    function myloginform( $username )
 *    {
 *      // see drawLogin for an example
 *    }
 *
 *    // create auth object
 *    $myauth = new Auth( $dsn, $options, 'myloginform', true);
 *
 *  You can now use the $myauth object on all your pages like 
 *  in the example above:
 *
 *    // start auth session
 *    $myauth->start();
 *
 *    if ($myauth->getAuth()) {
 *        // user has logged in 
 *    }
 *
 *  If you only want to check, if a user has logged in without
 *  displaying the login form,  use setShowLogin() before you 
 *  call $myauth->start() on your page:
 *
 *    // disable display of login form
 *    $myauth->setShowLogin( false );
 * 
 *    // start auth session
 *    $myauth->start();
 *
 *    if ($myauth->getAuth()) {
 *        // user has logged in 
 *    } else {
 *        // user has not logged in and NO login 
 *        // is displayed.
 *    }
 *
 *  To logout a user and redisplay the login form use a construct
 *  like this:
 *
 *    $myauth->start();
 *
 *    if ( $action == 'logout' ) {
 *        $myauth->logout();
 *        $myauth->start();
 *    }
 *
 *
 * Note: PEAR::Auth currently requires register_globals=on in
 *       your PHP configuration.
 *
 * @author  Martin Jansen <mj@php.net>
 * @package Auth
 * @version $Revision$
 */

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
    var $loginFunction = "";

    /**
     * Should the login form be displayed?
     *
     * @var   bool
     * @see   setShowlogin()
     */
    var $showLogin = true;

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
     * @param boolean   Should the login form be displayed if neccessary?
     */
    function Auth($storageDriver = "DB", $options = "", $loginFunction = "", $showLogin = true)
    {
        if ($loginFunction != "" && function_exists($loginFunction)) {
            $this->loginFunction = $loginFunction;
        }

        if (is_bool($showLogin)) {
            $this->showLogin = $showLogin;
        }

        $this->storage = $this->_factory($storageDriver, $options);
    }

    // }}}
    // {{{ _factory()

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
        $storage_path = "Auth/Container/" . $driver . ".php";
        $storage_class = "Auth_Container_" . $driver;

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
     * @access private
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
     * @access public
     */
    function start()
    {
        session_start();

        $this->assignData();

        if (!$this->checkAuth() && $this->showLogin) {
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
            $login_ok = $this->storage->fetchData($this->username, $this->password);
        }

        /**
         * If the login failed or the user entered no username,
         * output the login screen again.
         */
        if ($this->username != "" && !$login_ok) {
            $this->status = AUTH_WRONG_LOGIN;
        }

        if ($this->username == "" || !$login_ok) {
            $this->drawLogin($this->storage->activeUser);
            return;
        }
    }

    // }}}
    // {{{ setExpire()

    /**
     * Set the maximum expire time
     *
     * @access public
     * @param  integer time in seconds
     * @param  bool    add time to current expire time or not
     */
    function setExpire($time, $add = false)
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
     * @access public
     * @param  string Username
     * @param  array  Additional information that is stored in
     *                the session.
     */
    function setAuth($username, $data = array())
    {
        if (!isset($GLOBALS['HTTP_SESSION_VARS']['auth'])) {
            session_register('auth');
        }

        $GLOBALS['auth']               = &$GLOBALS['HTTP_SESSION_VARS']['auth'];
        $GLOBALS['auth']['registered'] = true;
        $GLOBALS['auth']['username']   = $username;
        $GLOBALS['auth']['timestamp']  = time();
        $GLOBALS['auth']['idle']       = time();

        if (count($data) > 0) {
            $GLOBALS['auth']['data']   = $data;
        }
    }

    // }}}
    // {{{ getAuth()

    /**
     * Has the user been authenticated?
     *
     * @access public
     * @return bool  True if the user is logged in, otherwise false.
     */
    function getAuth()
    {
        if ($GLOBALS['HTTP_SESSION_VARS']['auth']['registered'] == true) {
            return true;
        } else {
            return false;
        }
    }

    // }}}
    // {{{ setShowLogin()

    /**
     * Should the login form be displayed if neccessary?
     *
     * @access public
     * @param  bool    show login form or not
     */
    function setShowLogin($showLogin = true)
    {
        $this->showLogin = $showLogin;
    }

    // }}}
    // {{{ drawLogin()

    /**
     * Draw the login form
     *
     * Normally you will not use this output in your application,
     * because you can pass a different function name to the
     * constructor. For more information on this, please
     * consult the documentation.
     *
     * @access private
     * @global $HTTP_SERVER_VARS
     * @param  string  Username if already entered
     */
    function drawLogin($username = "")
    {
        if ($this->loginFunction != "") {
            call_user_func($this->loginFunction, $username, $this->status);
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
     * This function clears any auth tokens in the currently
     * active session
     *
     * @access public
     */
    function logout()
    {
        $this->username = "";
        $this->password = "";

        $GLOBALS['HTTP_SESSION_VARS']['auth'] = "";
        session_unregister("auth");
    }

    // }}}
    // {{{ updateIdle()

    /**
     * Update the idletime
     *
     * @access private
     */
    function updateIdle()
    {
        $GLOBALS['auth'] = &$GLOBALS['HTTP_SESSION_VARS']['auth'];
        $GLOBALS['auth']['idle'] = time();
    }

    // }}}
    // {{{ getUsername()

    /**
     * Get the username
     *
     * @access public
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
     * @access public
     * @return integer
     */
    function sessionValidThru()
    {
        return ($GLOBALS['HTTP_SESSION_VARS']['auth']['idle'] + $this->idle);
    }

    // }}}
    // {{{ listUsers()

    /**
     * List all users that are currently available in the storage
     * container
     *
     * @access public
     * @return array
     */
    function listUsers()
    {
        return $this->storage->listUsers();
    }

    // {{{ addUser()

    /**
     * Add user to the storage container
     *
     * @access public
     * @param  string Username
     * @param  string Password
     * @param  mixed  Additional parameters
     */    
    function addUser($username, $password, $additional = "")
    {
        return $this->storage->addUser($username, $password, $additional);
    }

    // }}}
    // {{{ removeUser()

    /**
     * Remove user from the storage container
     *
     * @access public
     * @param string Username
     */
    function removeUser($username)
    {
        return $this->storage->removeUser($username);
    }

    // }}}
}
?>
