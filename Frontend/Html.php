<?php

/**
  * Standard Html Login form
  * 
  */
class Auth_Frontend_Html {

    /**
      * Displays the login form
      *
      * @param object The calling auth instance
      * @return void
      */
    function render(&$caller, $username = '') {
        $server = &$caller->_importGlobalVariable('server');
        echo '<center>'."\n";
        if (!empty($caller->status) && $caller->status == AUTH_EXPIRED) {
            echo '<i>Your session has expired. Please login again!</i>'."\n";
        } else if (!empty($caller->status) && $caller->status == AUTH_IDLED) {
            echo '<i>You have been idle for too long. Please login again!</i>'."\n";
        } else if (!empty ($caller->status) && $caller->status == AUTH_WRONG_LOGIN) {
            echo '<i>Wrong login data!</i>'."\n";
        } else if (!empty ($caller->status) && $caller->status == AUTH_SECURITY_BREACH) {
            echo '<i>Security problem detected. </i>'."\n";
        }
        #PEAR::raiseError('You are using the built-in login screen of PEAR::Auth.<br />See the <a href="http://pear.php.net/manual/">manual</a> for details on how to create your own login function.', null);

        echo '<form method="post" action="' . $server['PHP_SELF'] . '">'."\n";
        echo '<table border="0" cellpadding="2" cellspacing="0" summary="login form">'."\n";
        echo '<tr>'."\n";
        echo '    <td colspan="2" bgcolor="#eeeeee"><b>Login:</b></td>'."\n";
        echo '</tr>'."\n";
        echo '<tr>'."\n";
        echo '    <td>Username:</td>'."\n";
        echo '    <td><input type="text" name="username" value="' . $username . '" /></td>'."\n";
        echo '</tr>'."\n";
        echo '<tr>'."\n";
        echo '    <td>Password:</td>'."\n";
        echo '    <td><input type="password" name="password" /></td>'."\n";
        echo '</tr>'."\n";
        echo '<tr>'."\n";
        echo '    <td colspan="2" bgcolor="#eeeeee"><input type="submit" /></td>'."\n";
        echo '</tr>'."\n";
        echo '</table>'."\n";
        echo '</form>'."\n";
        echo '</center>'."\n\n";
    }
    
}

?>
