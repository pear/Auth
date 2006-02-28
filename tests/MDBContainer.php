<?php

include_once 'TestAuthContainer.php';
include_once 'Auth/Container/MDB.php';


class MDBContainer extends TestAuthContainer {

    function MDBContainer($name){
        $this->TestAuthContainer($name);
    }

    function &getContainer() {
        static $container;
        #print "In MDBContainer::getContainer {$this->skip_tests}\n";
        if(!isset($container)){
            include './auth_container_mdb_options.php';
            $container = new Auth_Container_MDB($options);
            // Catch if DB connection cannot be made
            $res = $container->_prepare();
        }

        if(!MDB::isConnection($container->db)){
            #print "In MDBContainer::getContainer container->db is error \n";
            $this->skip_tests = true;
            $this->skip_tests_message = "SKIP TEST:MDB is not a connection object, check dsn !!!";
        }
        return $container;
    }

    function &getExtraOptions() {
        include './auth_container_mdb_options.php';
        return $extra_options;
    }
}




?>
