<?php

/*
        $this->options['table']       = "auth";
        $this->options['usernamecol'] = "username";
        $this->options['passwordcol'] = "password";
        $this->options['dsn']         = "";
        $this->options['db_fields']   = "";
        $this->options['cryptType']   = "md5";
*/
$options = array(
    'dsn'=>'mysql://root:@localhost/authtest',
    'table'=>'temp',
    'usernamecol'=>'username',
    'passwordcol'=>'password',
    'cryptType'=>'md5',
    'db_fields'=>'*'
);

$extra_options['username'] = 'test_user';
$extra_options['passwd'] = 'test_user';

?>
