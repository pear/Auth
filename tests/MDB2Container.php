<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/MDB2.php';


class MDB2Container extends TestAuthContainer {

    function MDB2Container($name){
        $this->TestAuthContainer($name);
    }

    function &getContainer() {
        static $container;
        #print "In MDB2Container::getContainer {$this->skip_tests}\n";
        if(!isset($container)){
            include './auth_container_mdb2_options.php';
            $container = new Auth_Container_MDB2($options);
            // Catch if DB connection cannot be made
            $res = $container->_prepare();
        }

        if(!MDB2::isConnection($container->db)){
            #print "In MDB2Container::getContainer container->db is error \n";
            $this->skip_tests = true;
            $this->skip_tests_message = "SKIP TEST:MDB2 is not a connection object, check dsn !!!";
        }
        return $container;
    }

    function &getExtraOptions() {
        include './auth_container_mdb2_options.php';
        return $extra_options;
    }
}
?>
