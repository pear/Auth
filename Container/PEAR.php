<?php

include_once('XML/RPC.php');

class Auth_Container_Pear {
    function Auth_Container_pear()
    {
    
    }
    
    function fetchData($username, $password)
    {
        $rpc = new XML_RPC_Client('/xmlrpc.php', 'pear.php.net');
        $rpc_message = new XML_RPC_Message("user.info", array(new XML_RPC_Value($username, "string")) );
        // Error Checking howto ???
        $result = $rpc->send($rpc_message);
        $value = $result->value();
        $userinfo = xml_rpc_decode($value);
        if ($userinfo['password'] == md5($password)) {
            $this->activeUser = $userinfo['handle'];
            foreach ($userinfo as $uk=>$uv) {
                $this->_auth_obj->setAuthData($uk, $uv);
            }
            return true;
        }
        return false;
    }
    
}
?>