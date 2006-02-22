<?php
/*
//TEST DATABASE:
-----------------------------------------------
DROP TABLE IF EXISTS temp;
CREATE TABLE temp (
  username varchar(150) NOT NULL,
  password varchar(200) NOT NULL
);
-----------------------------------------------
*/

$options = array(
    'dsn'         => 'mysql://root:@localhost/authtest',
    'table'       => 'temp',
    'usernamecol' => 'username',
    'passwordcol' => 'password',
    'db_fields'   => '*',
    'cryptType' => 'md5'
);

$extra_options['username'] = 'test_user';
$extra_options['passwd'] = 'test_user';

?>
