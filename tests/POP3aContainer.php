<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/POP3.php';


class POP3aContainer extends TestAuthContainer {


    function &getContainer() {
        static $container;
        if(!isset($container)){
            include 'auth_container_pop3a_options.php';
            $container = new Auth_Container_POP3($options);
        }
        return($container);
    }

    function &getExtraOptions() {
        include 'auth_container_pop3a_options.php';
        return($extra_options);
    }
}




?>
