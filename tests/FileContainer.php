<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/File.php';

class FileContainer extends TestAuthContainer {


    function &getContainer() {
        static $container;
        if(!isset($container)){
            include 'auth_container_file_options.php';
            $container = new Auth_Container_File($options);
        }
        return($container);
    }

    function &getExtraOptions() {
        include 'auth_container_file_options.php';
        return($extra_options);
    }
}




?>
