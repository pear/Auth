<?php
//
// +----------------------------------------------------------------------+
// | PHP version 4.0                                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2001 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.02 of the PHP license,      |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Martin Jansen <mj@php.net>                                  |
// +----------------------------------------------------------------------+
//
// $Id$
//

/**
 * Storage class for fetching login data
 *
 * @author   Martin Jansen <mj@php.net>
 * @package  Auth
 */
class Auth_Container
{

    // {{{ Constructor

    /**
     * Constructor
     *
     * Has to be overwritten by each storage class
     *
     * @access public
     */
    function Auth_Container()
    {
    }

    // }}}
    // {{{ fetchData()

    /**
     * Fetch data from storage container
     *
     * Has to be overwritten by each storage class
     *
     * @access public
     */
    function fetchData() 
    {
    }
    
    // }}}
}
?>
