<?php

include_once 'PHPUnit.php';


class TestAuthContainer extends PHPUnit_TestCase
{

    var $skip_tests = false;
    var $skip_tests_message = "SKIP TEST";

    function TestAuthContainer($name)
    {
        $this->PHPUnit_TestCase($name);
        $this->container =& $this->getContainer();
        $this->user = 'joe';
        $this->pass = 'doe';
        $this->opt = 'Very cool user';
    }

    // Abstract
    function getContainer() {}
    function getExtraOptions() {}

    function setUp()
    {
        $opt = $this->getExtraOptions();
        // Add the default user to be used for some testing
        $this->container->addUser($opt['username'], $opt['passwd']);
    }

    function tearDown()
    {
        $opt = $this->getExtraOptions();
        // Remove default user
        $this->container->removeUser($opt['username']);
    }

    function testListUsers()
    {
        if ($this->skip_tests) {
            $this->fail($this->skip_tests_message.'');
            return(false);
        }

        $users = $this->container->listUsers();
        if (AUTH_METHOD_NOT_SUPPORTED === $users) {
            $this->fail('This operation is not supported by '.get_class($this->container));
            return(false);
        }

        $opt = $this->getExtraOptions();
        $this->assertTrue(is_array($users[0]), 'First array element from result was not an array');
        $this->assertTrue($users[0]['username'] == $opt['username'], sprintf('First username was not equal to default username "%s" ', $opt['username']));
    }

    function testAddUser()
    {
        if ($this->skip_tests) {
            $this->fail($this->skip_tests_message.'');
            return(false);
        }

        $cb = count($this->container->listUsers());
        $res = $this->container->addUser($this->user, $this->pass, $this->opt);
        if (AUTH_METHOD_NOT_SUPPORTED === $res) {
            $this->fail("This operation is not supported by ".get_class($this->container));
            return(false);
        }

        if (PEAR::isError($res)) {
            $error = $res->getMessage().' ['.$res->UserInfo().']';
        } else {
            $error = '';
        }
        $this->assertTrue(!PEAR::isError($res), 'error:'.$error);
        $ca = count($this->container->listUsers());
        $users = $this->container->listUsers();
        $last_username = $users[$ca-1]['username'];
        $this->assertTrue( ($cb === $ca-1) , sprintf('Count of users before (%s) and after (%s) does not differ by one', $cb, $ca));
        $this->assertTrue( $this->container->fetchData($this->user, $this->pass) , sprintf('Could not verify with the newly created user %s',$this->user));

        // Remove the user we just added, assumes removeUser works
        $this->container->removeUser($this->user);
    }

    function testFetchData()
    {
        if ($this->skip_tests) {
            $this->fail($this->skip_tests_message.'');
            return(false);
        }

        $opt = $this->getExtraOptions();
        $fetch_res = $this->container->fetchData($opt['username'], $opt['passwd']);
        if (AUTH_METHOD_NOT_SUPPORTED === $fetch_res) {
            $this->fail("This operation is not supported by ".get_class($this->container));
            return(false);
        }

        $this->assertTrue($fetch_res,sprintf('Could not verify with the default username (%s) and passwd (%s)', $opt['username'], $opt['passwd']));
    }

    function testFetchDataFail()
    {
        if ($this->skip_tests) {
            $this->fail($this->skip_tests_message.'');
            return(false);
        }

        $opt = $this->getExtraOptions();
        $this->assertTrue(
            $this->container->fetchData(md5($opt['username']), $opt['passwd']),
            sprintf('This test should fail ... ')
        );
    }

    function testRemoveUser()
    {
        if ($this->skip_tests) {
            $this->fail($this->skip_tests_message.'');
            return(false);
        }

        // Add a user to be removed when testing removeUuser method
        // Assume add user works
        $this->container->addUser('for_remove', 'for_remove');
        $cb = count($this->container->listUsers());
        $remove_res = $this->container->removeUser('for_remove');
        if (AUTH_METHOD_NOT_SUPPORTED === $remove_res) {
            $this->fail("This operation is not supported by ".get_class($this->container));
            return(false);
        }

        $this->assertTrue(AUTH_METHOD_NOT_SUPPORTED == $remove_res, "This operation is not supported by ".get_class($this));
        $ca = count($this->container->listUsers());
        $this->assertTrue($cb === $ca+1, sprintf('Could not remove user "%s", count before:%s count after:%s ', 'for_remove', $cb, $ca));
    }

}

?>