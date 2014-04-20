<?php
require_once 'Log/observer.php';
class Auth_Log_Observer extends Log_observer {
  protected $_logger;

  function __construct($priority, $logger) {
      $this->_id = md5(microtime());
      $this->_priority = $priority;
      $this->_logger = $logger;
  }

  function notify($event) {
    $this->_logger->log($event['message'], $event['priority']);
  }
}