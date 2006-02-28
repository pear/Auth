<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/IMAP.php';


class IMAPContainer extends TestAuthContainer {

    function IMAPContainer($name){
        $this->TestAuthContainer($name);
    }
    
    function &getContainer() {
        print "IMAPContainer::getContainer\n";
        static $container;
        if(!isset($container)){
            include './auth_container_imap_options.php';
            $container = new Auth_Container_IMAP($options);
        }
        return($container);
    }
    
    function &getExtraOptions() {
        print "IMAPContainer::getExtraOptions\n";
        include './auth_container_imap_options.php';
        return($extra_options);
    }
}




?>
