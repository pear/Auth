<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
/*
Copyright (c) 2003, Michael Bretterklieber <michael@bretterklieber.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions 
are met:

1. Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright 
   notice, this list of conditions and the following disclaimer in the 
   documentation and/or other materials provided with the distribution.
3. The names of the authors may not be used to endorse or promote products 
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This code cannot simply be copied and put under the GNU Public License or 
any other GPL-like (LGPL, GPL2) License.

    $Id$
*/

require_once "Auth/Container.php";
require_once "Auth_RADIUS/RADIUS.php";

/*
 * Storage driver for authenticating users against RADIUS servers.
 *
 * @author  Michael Bretterklieber <michael@bretterklieber.com>
 * @access  public
 * @version $Revision$
 */
class Auth_Container_RADIUS extends Auth_Container
{
    /**
     * Contains a RADIUS object
     * @var object
     */
    var $radius;
    
    /**
     * Contains the authentication type
     * @var string
     */
    var $authtype;    

    /**
     * Constructor of the container class.
     *
     * $options can have these keys:
     * 'servers'    an array containing an array: servername, port, sharedsecret, timeout, maxtries
     * 'configfile' The filename of the configurationfile
     * 'authtype'   The type of authentication, one of: PAP, CHAP_MD5, MSCHAPv1, MSCHAPv2, default is PAP
     *
     * @param  $options associative array with 
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_RADIUS($options)
    {
        $this->authtype = 'PAP';
        if (isset($options['authtype'])) {
            $this->authtype = $options['authtype'];
        }
        $classname = 'Auth_RADIUS_' . $this->authtype;
        if (!class_exists($classname)) {
            PEAR::raiseError("Unknown Authtype, please use on of: PAP, CHAP_MD5, MSCHAPv1, MSCHAPv2!",
                                    41, PEAR_ERROR_DIE);
        }
        
        $this->radius = new $classname;

        if (isset($options['configfile'])) {
            $this->radius->setConfigfile($options['configfile']);
        }

        $servers = $options['servers'];
        if (is_array($servers)) {
            foreach ($servers as $server) {
                $servername     = $server[0];
                $port           = isset($server[1]) ? $server[1] : 0;
                $sharedsecret   = isset($server[2]) ? $server[2] : 'testing123';
                $timeout        = isset($server[3]) ? $server[3] : 3;
                $maxtries       = isset($server[4]) ? $server[4] : 3;
                $this->radius->addServer($servername, $port, $sharedsecret, $timeout, $maxtries);
            }
        }
        
        if (!$this->radius->start()) {
            PEAR::raiseError($this->radius->getError(), 41, PEAR_ERROR_DIE);
        }
    }

    /**
     * Authenticate
     *
     * @param  string Username
     * @param  string Password
     * @return bool   true on success, false on reject
     */
    function fetchData($username, $password, $challenge = null)
    {
        switch($this->authtype) {
        case 'CHAP_MD5':
        case 'MSCHAPv1':
            if (isset($challenge)) {
                echo $password;
                $this->radius->challenge = $challenge;
                $this->radius->chapid    = 1;
                $this->radius->response  = pack('H*', $password);
            } else {
                require_once 'Crypt_CHAP/CHAP.php';
                $classname = 'Crypt_' . $this->authtype;
                $crpt = new $classname;
                $crpt->password = $password;
                $this->radius->challenge = $crpt->challenge;
                $this->radius->chapid    = $crpt->chapid;
                $this->radius->response  = $crpt->challengeResponse();
                break;
            }
  
        case 'MSCHAPv2':
            require_once 'Crypt_CHAP/CHAP.php';
            $crpt = new Crypt_MSCHAPv2;
            $crpt->username = $username;
            $crpt->password = $password;
            $this->radius->challenge     = $crpt->authChallenge;
            $this->radius->peerChallenge = $crpt->peerChallenge;
            $this->radius->chapid        = $crpt->chapid;
            $this->radius->response      = $crpt->challengeResponse();
            break;
    
        default:
            $this->radius->password = $password;
            break;
        }
        
        $this->radius->username = $username;
        
        $this->radius->putAuthAttributes();
        $result = $this->radius->send();
        if (PEAR::isError($result)) {
            return false;
        }

        $this->radius->getAttributes();
        $this->radius->dumpAttributes();
        
        return $result;
    }
}
?>
