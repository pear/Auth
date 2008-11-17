<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/DBLite.php';


class DBLiteContainer extends TestAuthContainer {

    function &getContainer() {
        static $container;
        #print "In DBContainer::getContainer {$this->skip_tests}\n";
        if(!isset($container)){
            include 'auth_container_db_options.php';
            $container = new Auth_Container_DBLite($options);
            // Catch if DB connection cannot be made
            $res = $container->_prepare();
        }

        if(!DB::isConnection($container->db)){
            $this->markTestSkipped("DB is not a connection object, check dsn");
        }
        return($container);
    }

    function &getExtraOptions() {
        include 'auth_container_db_options.php';
        return($extra_options);
    }
}




?>
