<?php

class Auth_Controller {

    var $auth_obj = null;
    var $login = null;
    var $default = null;
    
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
        if($_GET['return'] && !strstr($_GET['return'], $this->_loginPage)) {
            print "Return: {$_GET['return']} <br/>";
            $this->auth->setAuthData('returnUrl', $_GET['return']);
        }
        
        //if()
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

        if(!strstr($_SERVER['PHP_SELF'], $this->_loginPage)) {
            $url .= 'return='.urlencode($_SERVER['PHP_SELF']);
        }
        header('Location:'.$url);
        print("You could not be redirected to <a href=\"$url\">$url</a>");
    }
    
    
    function start() {
        // Check the accessList here
        if(!$this->auth->checkAuth()) {
            $this->redirectLogin();
        }
    }
    
    function isAuthorised() {
        return($this->auth->checkAuth());
    }
}

?>
