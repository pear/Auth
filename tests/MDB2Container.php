<?php

require_once 'TestAuthContainer.php';
require_once 'Auth/Container/MDB2.php';


class MDB2Container extends TestAuthContainer {

    function &getContainer() {
        static $container;

        if (!isset($container)) {
            include 'auth_container_mdb2_options.php';
            $container = new Auth_Container_MDB2($options);
            // Catch if DB connection cannot be made
            $res = $container->_prepare();
        }

        if (!MDB2::isConnection($container->db)) {
            $this->markTestSkipped("MDB2 is not a connection object, check dsn");
        }

        return $container;
    }

    function &getExtraOptions() {
        include 'auth_container_mdb2_options.php';
        return $extra_options;
    }
}
?>
