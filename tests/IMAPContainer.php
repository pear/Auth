<?php

require_once 'TestAuthContainer.php';
require_once 'Auth/Container/IMAP.php';


class IMAPContainer extends TestAuthContainer {


    function &getContainer() {
        static $container;

        if (!extension_loaded('imap')) {
            $this->markTestSkipped("This test needs the IMAP extension");
        }

        if(!isset($container)){
            include 'auth_container_imap_options.php';
            $container = new Auth_Container_IMAP($options);
        }
        return($container);
    }

    function &getExtraOptions() {
        print "IMAPContainer::getExtraOptions\n";
        include 'auth_container_imap_options.php';
        return($extra_options);
    }
}




?>
