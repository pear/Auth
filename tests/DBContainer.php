<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/DB.php';


class DBContainer extends TestAuthContainer {


    function &getContainer() {
        static $container;

        if(!isset($container)){
            include 'auth_container_db_options.php';
            $container = new Auth_Container_DB($options);
            // Catch if DB connection cannot be made
            $res = $container->_prepare();
        }

        if (!DB::isConnection($container->db)) {
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
