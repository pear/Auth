<?php

/**
  * Controlls access to a group of php access 
  * and redirects to a predefined login page as 
  * needed
  *
  * In all pages
  * <code>
  * include_once('Auth.php');
  * include_once('Auth/Controller.php');
  * $_auth = new Auth('File', 'passwd');
  * $authController = new Auth_Controller($_auth, 'login.php', 'index.php');
  * $authController->start();
  * </code>
  *
  * In login.php
  * <code>
  * include_once('Auth.php');
  * include_once('Auth/Controller.php');
  * $_auth = new Auth('File', 'passwd');
  * $authController = new Auth_Controller($_auth, 'login.php', 'index.php');
  * $authController->start();
  * if( $authController->isAuthorised() ){
  *   $authController->redirectBack();
  * }  
  * </code>
  *
  */
class Auth_Controller {

    /** var Auth An auth instance */
    var $auth = null;
    /** var string The login url */
    var $login = null;
    /** var string The default index page, used when login redirects and the caller page in not set or is the login page it's self */
    var $default = null;
    /** var bool If this is set to true auther a succesfull login the Auth_Controller::redirectBack() is invoked automatically */
    var $autoRedirectBack = false;
    
    /**
      * Constructor
      *
      * @param Auth An auth instance
      * @param string The login page
      * @param string The default page to go to if return page is not set
      * @param array Some rules about which urls need to be sent to the login page
      *
      * @todo Add a list of urls which need redirection
      */
    function Auth_Controller(&$auth_obj, $login='login.php', $default='index.php', $accessList=array()) {
        #print $auth_obj;
        $this->auth =& $auth_obj;
        $this->_loginPage = $login;
        $this->_defaultPage = $default;
        @session_start();
        if (!empty($_GET['return']) && $_GET['return'] && !strstr($_GET['return'], $this->_loginPage)) {
            #print "Return: {$_GET['return']} <br/>";
            $this->auth->setAuthData('returnUrl', $_GET['return']);
        }

        if(!empty($_GET['authstatus']) && $this->auth->status == '') {
            $this->auth->status = $_GET['authstatus'];
        }
    }
    
    /** 
      * Enables auto redirection when login is done
      * 
      * @param bool Sets the autoRedirectBack flag to this
      * @see Auth_Controller::autoRedirectBack
      *
      */
    function setAutoRedirectBack($flag = true){
        $this->autoRedirectBack = $flag;
    }
    
    /**
      * Redirects Back to the calling page
      */
    function redirectBack() {
        // If redirectback go there
        // else go to the default page
        
        $returnUrl = $this->auth->getAuthData('returnUrl');
        if(!$returnUrl) {
            $returnUrl = $this->_defaultPage;
        }
        
        // Add some entropy to the return to make it unique
        // avoind problems with cached pages and proxies
        if(strpos($returnUrl, '?') === false) {
            $returnUrl .= '?';
        }
        $returnUrl .= uniqid('');

        // Track the auth status
        if($this->auth->status != '') {
            $url .= '&authstatus='.$this->auth->status;
        }        
        header('Location:'.$returnUrl);
        print("You could not be redirected to <a href=\"$returnUrl\">$returnUrl</a>");
    }
    
    /**
      * Redirects to the login Page
      * if not authorised
      * 
      * put return page on the query or in auth
      */
    function redirectLogin() {
        // Go to the login Page
        
        // For Auth, put some check to avoid infinite redirects, this should at least exclude
        // the login page
        
        $url = $this->_loginPage;
        if(strpos($url, '?') === false) {
            $url .= '?';
        }

        #print "ServerPhp:".$_SERVER['PHP_SELF'];
        if(!strstr($_SERVER['PHP_SELF'], $this->_loginPage)) {
            $url .= 'return='.urlencode($_SERVER['PHP_SELF']);
        }
        // Track the auth status
        if($this->auth->status != '') {
            $url .= '&authstatus='.$this->auth->status;
        }
        header('Location:'.$url);
        print("You could not be redirected to <a href=\"$url\">$url</a>");
    }
    
    /**
      * Starts the Auth Procedure
      *
      * If the page requires login the user is redirected to the login page
      * otherwise the Auth::start is called to initialize Auth
      *
      * @todo Implement an access list which specifies which urls/pages need login and which do not
      */
    function start() {
        // Check the accessList here
        // ACL should be a list of urls with allow/deny
        // If allow set allowLogin to false
        // Some wild card matching should be implemented ?,*
        if(!strstr($_SERVER['PHP_SELF'], $this->_loginPage) && !$this->auth->checkAuth()) {
            $this->redirectLogin();
        } else {
            $this->auth->start();
            // Logged on and on login page
            if(strstr($_SERVER['PHP_SELF'], $this->_loginPage) && $this->auth->checkAuth()){
                $this->autoRedirectBack ? 
                    $this->redirectBack() :
                    null ;
            }
        }
        
        
    }
  
    /**
      * Checks is the user is logged on
      * @see Auth::checkAuth()
      */
    function isAuthorised() {
        return($this->auth->checkAuth());
    }

    /**
      * Proxy call to auth
      * @see Auth::checkAuth()
      */
    function checkAuth() {
        return($this->auth->checkAuth());
    }

    /**
      * Proxy call to auth
      * @see Auth::logout()
      */
    function logout() {
        return($this->auth->logout());
    }

    /**
      * Proxy call to auth
      * @see Auth::getUsername()
      */
    function getUsername() {
        return($this->auth->getUsername());
    }

    /**
      * Proxy call to auth
      * @see Auth::getStatus()
      */
    function getStatus(){
        return($this->auth->getStatus());
    }


}

?>
