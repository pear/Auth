<?php


include_once 'Auth.php';

/**
 * This class provides anonymous authentication
 * if username and password were not supplied
 *
 */
class Auth_Anonymous extends Auth {

    var $allow_anonymous = true;
    var $anonymous_username = 'anonymous';
    
    /**
      * Pass all parameters to Parent Auth class
      */
    function Auth_Anonymous($storageDriver, $options = '', $loginFunction = '', $showLogin = true) {
        parent::Auth($storageDriver, $options, $loginFunction, $showLogin);
    }
    
    /**
      * If no username & password is passed
      * then login the user as anonymous
      */
    function login() {
        if ( $this->allow_anonymous && empty($this->username) && empty($this->password) ) {
            $this->setAuth($this->anonymous_username);
            if (is_callable($this->loginCallback)) {
                call_user_func_array($this->loginCallback, array($this->username, &$this) );
            }
        } else {
            print "Real Login";
            parent::login();
        }
    }
    
    /**
      * Force the user to login
      *
      */
    function forceLogin() {
        $this->allow_anonymous = false;
        if( !empty($this->session['username']) && $this->session['username'] == $this->anonymous_username ) {
            $this->logout();
        }
    }
}

?>
