<?php
if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'Auth_AllTests::main');
}

require_once 'PHPUnit/TextUI/TestRunner.php';

require_once 'DBContainer.php';
require_once 'DBLiteContainer.php';
require_once 'POP3Container.php';
require_once 'POP3aContainer.php';
require_once 'FileContainer.php';
require_once 'MDBContainer.php';
require_once 'MDB2Container.php';
require_once 'IMAPContainer.php';

class Auth_AllTests
{
    public static function main()
    {

        PHPUnit_TextUI_TestRunner::run(self::suite());
    }

    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('Auth Tests');

        $suite->addTestSuite('DBContainer');
        $suite->addTestSuite('MDBContainer');
        //$suite->addTestSuite('MBD2Container');
        $suite->addTestSuite('DBLiteContainer');
        $suite->addTestSuite('POP3Container');
        $suite->addTestSuite('POP3aContainer');
        $suite->addTestSuite('FileContainer');
        $suite->addTestSuite('IMAPContainer');

        return $suite;
    }
}


// exec test suite
if (PHPUnit_MAIN_METHOD == 'Auth_AllTests::main') {
    Auth_AllTests::main();
}
?>
