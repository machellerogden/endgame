<?php
/**
 *  ______ _______ _____  ______ _______ _______ ______ 
 * |    __|    |  |     \|    __|   _   |       |    __|
 * |    __|  | |  |  |   |   |  |       |  | |  |    __|
 * |______|__|____|_____/|______|___|___|__|_|__|______|
 *
 * A RESTful PHP-Based API Development Framework
 *
 * @category    Pixel Dreamer
 * @package     Endgame
 * @copyright   2011 Pixel Dreamer LLC
 * @license     MIT (see LICENSE)
 * @version     0.5
 * @author      C Mac Heller-Ogden
 *
 */

class Endgame {
  
  public $config;
  public $mappings = array();
  public $output = array();
  public $user = array();
  public $request;
  public $session;
  public $security;
  public $sort;
  public $resource_key;
  
  protected function __construct($config=array()){
    // load config
    $this->config = new ArrayWrapper($config);
    // initialize output array
    $this->resetOutput();
    // create MultiSort instance
    $this->multiSort = new MultiSort();
    // setup endgame log
    $this->endgame_log = new Log($this->config->endgame_log_path);
    // setup security class
    $this->security = new Security($this->config->salt1,$this->config->salt2);
    // set request handler
    $this->request = new RequestWrapper();
    // create resource key, only used by throttle right now but could be useful for other things
    $this->resource_key = $_SERVER['REQUEST_METHOD'].preg_replace("/[^a-zA-Z0-9\s]/",'_',$_SERVER['REDIRECT_URL']);
    // get username
    if(isset($_SERVER['PHP_AUTH_USER'])){
      $this->user['username'] = $_SERVER['PHP_AUTH_USER'];
    } else if ($this->request->check('auth_user')){
      $this->user['username'] = $this->request->auth_user;
    } else {
      $this->user['username'] = false;
    }
    // get password
    if(isset($_SERVER['PHP_AUTH_PW'])){
      $this->user['password'] = $_SERVER['PHP_AUTH_PW'];
    } else if ($this->request->check('auth_pw')){
      $this->user['password'] = $this->request->auth_pw;
    } else {
      $this->user['password'] = false;
    }
    if ($this->user['username']!==false) {
      // start session with id set as a hash of client's IP address + username
      $this->session = new SessionWrapper( md5( $this->security->clientIP() . $this->user['username'] ) , 'endgame_session' );
    } else {
      $this->session = new SessionWrapper(null,'endgame_session');
    }
    $this->session->open();
  }
  
  public function auth($permit=DEFAULT_AUTH_PERMIT){
    $permissions = $this->security->bitMask($permit);
    // first try to verify via session_id so we can avoid calling the database if possible
    if($this->session->check('username')){
      if(in_array($this->session->group,$permissions)){
        $this->endgame_log->message('resume authenticated session -- username: '.$this->session->username.' -- user_id: '.$this->session->user_id.' -- session_id: '.$this->session->id);
        return true;
      } else {
        $this->output['meta']['message'] = 'Insufficient Permissions';
        $this->send();
      }
    }
    // get username and password (as set in constructor)
    $user = $this->user['username'];
    $pass = $this->user['password'];
    // make sure they are indeed set
    if(($user!==false)&&($pass!=false)){
      // connect to db
      mysql_connect($this->config->db_host,$this->config->db_user,$this->config->db_pass);
      // grab all rows matching username
      $query = "SELECT * FROM {$this->config->db_name}.{$this->config->auth_table} WHERE `{$this->config->auth_userfield}` = '{$this->security->escape_mysql($user)}';";
      $result = mysql_query($query);
      if (!$result) die('Invalid Query: '.mysql_error());
      $result = mysql_fetch_array($result);
      // if query was successful
      if($result[0]!==false){
        // hash the user-supplied password
        $hash = $this->security->hash($pass);
        $group = $result[$this->config->auth_groupfield];
        if(in_array($group,$permissions)){
          // ...and see if it matches the password from the db
          if($hash == $result[$this->config->auth_passfield]){
            // ...if it does, save some stuff to the session
            $this->session->user_id = $result['id'];
            $this->session->group = $group;
            $this->session->username = $user;
            // ...and load the session name and id into the output array
            $this->endgame_log->message('login -- username: '.$user.' -- user_id: '.$result['id'].' -- session_id: '.session_id());
            return true;
          } else {
            $this->output['meta']['message'] = 'Wrong Password';
            $this->endgame_log->message('unsuccessful login: wrong password');
          }
        } else {
          $this->output['meta']['message'] = 'Insufficient Permissions';
          $this->endgame_log->message('unsuccessful login: insufficient permissions');
        }
      } else {
        $this->output['meta']['message'] = 'Username Not Found';
        $this->endgame_log->message('unsuccessful login: username not found');
      }
    } else {
      $this->output['meta']['message'] = 'Missing Authentication Credentials';
      $this->endgame_log->message('unsuccessful login: missing auth creds');
    }
    return false;
  }
  
  public function deny(){
    $this->resetOutput();
    $this->send('401');
  }
  
  public function register($group=false){
    $group = ($group!==false) ? $group : DEFAULT_GROUP;
    // dnsbl blacklist check
    $ip = $this->security->clientIP();
    $blacklisted = $this->security->blacklistCheck($ip);
    if($blacklisted){
      $this->endgame_log->message('blacklisted IP attempt to register failed');
      $this->sendError('Access Denied: Your IP appears to be blacklisted. If believe you\'re receiving this message in error please contact '.$this->config->admin_email);
    } else {
      // get username and password from POST if set, else set false
      $u = $this->request->check('username') ? $this->request->username : false;
      $p = $this->request->check('password') ? $this->request->password : false;
      // if neither are false...
      if($u&&$p){
        // should username should be an email, if so validate, otherwise set true (valid)
        $userck = ($this->config->auth_userfieldisemail) ? $this->security->validateEmail($u) : true;
        // if username validates
        if($userck){
          mysql_connect($this->config->db_host,$this->config->db_user,$this->config->db_pass);
          // escape username for query
          $u = $this->security->escape_mysql($u);
          // hash the password
          $p = $this->security->hash($p);
          // query db
          $query = "INSERT INTO {$this->config->db_name}.{$this->config->auth_table} ({$this->config->auth_userfield}, {$this->config->auth_passfield}, {$this->config->auth_groupfield}) VALUES ('{$u}', '{$p}','{$group}');";
          $result = mysql_query($query);
          if ($result) {
            $this->endgame_log->message('successful registration - username:'.$u);
            $this->output['meta']['message'] = 'Account Registration Successful';
            $this->send();
          } else {
            $this->sendError('Invalid Request: '.mysql_error());
          }
        }
        $emailerror = ($this->config->auth_userfieldisemail) ? ' - must be valid email address' : '';
        $this->sendError('Invalid Username'.$emailerror,false);
      } else {
        $this->sendError('Missing Required Fields',false);
      }
    }
  }
  
  
  public function run(){
    $this->throttle($this->config->global_throttle_limit,$this->config->global_throttle_window,'global_throttle');
    // this is our first loop through mappings to separate out the url and parameter names
    for($i=0;$i<sizeof($this->mappings);$i++){
      if(strpos($this->mappings[$i]['url'],':')!==false){
        // First, we explode the mapping into an array containing the url along side the paramater names...
        $this->mappings[$i]['pnames'] = explode('/:',$this->mappings[$i]['url']);
        // ... and then we shift the url off the the front of the parameter names array and into the mapping url.
        $this->mappings[$i]['url'] = array_shift($this->mappings[$i]['pnames']);
        // now we have a nice clean url in the mapping url a new array containing all the parameter names
      } else {
        $this->mappings[$i]['pnames'] = false;
      }
    }
    // sort mappings by string length of their url, longest first
    $this->mappings = $this->multiSort->byKeyLength($this->mappings,'url');
    // at this point we still haven't called any user methods, but we're about try so set called to false
    $called = false;
    // check to see if we're at the app root
    $root = is_null($_SERVER['REDIRECT_URL']) ? true : false;
    // if this is an option request, authenticate and report
    if($_SERVER['REQUEST_METHOD']=='OPTIONS') {
      $this->auth(PERMIT_ALL_USERS) or $this->deny();
      $found = false;
      foreach($this->mappings as $mapping){
        if(!$root&&strpos($_SERVER['REDIRECT_URL'],$mapping['url'])!==false){
          $found = true;
          if (!in_array($mapping['httpMethod'],$this->output['data'])) $this->output['data'][] = $mapping['httpMethod'];
        }
      }
      if (!$found) $this->sendError('Specified Resource Not Found');
      else $this->send();
    }
    // another loop through mappings, this time to match and call the user method
    for($i=0;$i<sizeof($this->mappings);$i++){
      // if the mapping url is in the url or if its a root mapping
      if(!$root&&strpos($_SERVER['REDIRECT_URL'],$this->mappings[$i]['url'])!==false) {
        // if method is valid
        $method_is_valid = ($_SERVER['REQUEST_METHOD']==$this->mappings[$i]['httpMethod']) ? true : false;
        if ($method_is_valid) {
          if($this->mappings[$i]['pnames']!==false){
            // get just the values substring of the url
            $paramValues = str_replace($this->mappings[$i]['url'],'',$_SERVER['REDIRECT_URL']);
            // if the first character is a forward slash, remove it
            $paramValues = ($paramValues[0] == '/') ? substr($paramValues,1) : $paramValues;
            // try to explode values into an array...
            if($values = explode('/',$paramValues)){
              // ...and if that works, combine the names and values into the final parameter array
              $params = array_combine($this->mappings[$i]['pnames'],$values);
              if($params){
                  // ...and if that worked go ahead and call the user method!!!!
                  call_user_func_array(array($this,$this->mappings[$i]['methodName']),array($params));
                  $called = true; // the user method has been called!
              } else {
                // ...but if that didn't work send an error
                $this->sendError('Wrong Number of Parameters');
              }
              break; // break loop now, we only want the first match
            }
          } else {
            call_user_func(array($this,$this->mappings[$i]['methodName']));
            $called = true; // the user method has been called!
            break; // break loop now, we only want the first match
          }
        }
      }
    }
    if(!$called){
      if($root){
        $this->output['message'] = $this->config->root_message;
        $this->render();
      }
      if ($method_is_valid===false) $this->sendError('Invalid Request Method');
      $this->sendError('Specified Resource Not Found');
    }
    exit;
  }
  
  protected function send($code='200',$format='json'){
    mysql_close();
    ob_start(); // start output buffer
    switch($code){
      case '200':
        $status = 'OK';
        break;
      case '400':
        $status = 'Bad Request';
        break;
      case '401':
        $status = 'Unauthorized';
        header('WWW-Authenticate: Basic realm="'.$this->config->app_name.'"');
        break;
    }
    $this->output['meta']['code'] = $code;
    $this->output['meta']['status'] = $status;
    header('HTTP/1.1 '.$code.' '.$status);
    switch($format){
      case 'json':
        header('Content-Type: application/json');
        echo json_encode($this->output);
        break;
      case 'xml':
        $xml = new XmlWriter();
        $xml->openMemory();
        $xml->startDocument('1.0', 'UTF-8');
        $xml->startElement('envelope');
        $this->writeXML($xml, $this->output);
        $xml->endElement();
        header('Content-Type: application/xhtml+xml');
        echo $xml->outputMemory(true);
        break;
    }
    ob_end_flush(); // flush output buffer
    exit;
  }
  
  public function sendError($message='',$auth=true) {
    mysql_close();
    if($auth){ $this->auth(PERMIT_ALL_USERS) or $this->deny(); }
    $this->output['meta']['message'] = $message;
    $this->send('400');
  }
  
  protected function sendFile($filename, $contentType, $path) {
    mysql_close();
    header('Content-type: $contentType');
    header('Content-Disposition: attachment; filename='.$filename.';');
    ob_clean();
    flush();
    readfile($path);
    exit;
  }
  
  protected function sendDownload($filename, $path) {
    mysql_close();
    header('Content-Type: application/force-download');
    header('Content-Type: application/octet-stream');
    header('Content-Type: application/download');
    header('Content-Description: File Transfer');
    header('Content-Disposition: attachment; filename='.$filename.';');
    header('Content-Transfer-Encoding: binary');
    ob_clean();
    flush();
    readfile($path);
    exit;
  }
  
  protected function render($view='text'){
    mysql_close();
    ob_start();
    header('Content-Type: text/html;charset=utf-8');
    foreach($this->output as $k => $v){
      if (empty($v)) unset($this->output[$k]); // get rid of empty elements
    }
    extract($this->output, EXTR_PREFIX_ALL, 'var');
    include 'views/'.$view.'.php';
    ob_end_flush();
    exit;
  }
  
  protected function writeXML(XMLWriter $xml, $data){
    foreach($data as $key => $value){
      if(is_array($value)){
        $xml->startElement($key);
        $this->writeXML($xml, $value);
        $xml->endElement();
        continue;
      }
      $xml->writeElement($key, $value);
    }
  }
  
  protected function resetOutput(){
    $this->output['meta']['code'] = '';
    $this->output['meta']['status'] = '';
    $this->output['data'] = array();
  }
  
  protected function throttle($limit=100,$window=60,$resource_key=false){
    $resource_key = ($resource_key===false) ? $this->resource_key : $resource_key;
    if(!isset($_SESSION[$resource_key]['last_request'])){
      $_SESSION[$resource_key]['last_request'] = time();
      $_SESSION[$resource_key]['min_throttle'] = 0;
      $this->output['meta']['hits_available'] = $limit;
    } else {
      $last_request = $_SESSION[$resource_key]['last_request'];
      $last_diff = time() - $last_request;
      $throttle = $_SESSION[$resource_key]['min_throttle'];
      $new_throttle = $throttle - $last_diff;
      $new_throttle = $new_throttle < 0 ? 0 : $new_throttle;
      $new_throttle += $window / $limit;
      $hits_available = floor( ( $window - $new_throttle ) * $limit / $window  );
      $hits_available = $hits_available >= 0 ? $hits_available : 0;
      if ( $new_throttle > $window ) {
        $wait = ceil( $new_throttle - $window );
        usleep( 250000 );
        if($resource_key==='global_throttle'){
          $this->endgame_log->message('global throttle limit hit -- username: '.$this->session->username.' -- user_id: '.$this->session->user_id);
          $this->sendError('Your API request limit has been reached. Please wait '.$wait.' seconds before attempting again.');
        } else {
          $this->endgame_log->message('resource throttle limit hit -- username: '.$this->session->username.' -- user_id: '.$this->session->user_id);
          $this->sendError('Your API request limit for this resource has been reached. Please wait '.$wait.' seconds before attempting again.');
        }
      }
      if ($resource_key==='global_throttle') $this->output['meta']['global_hits_available'] = $hits_available;
      else $this->output['meta']['resource_hits_available'] = $hits_available;
      $_SESSION[$resource_key]['last_request'] = time();
      $_SESSION[$resource_key]['min_throttle'] = $new_throttle;
    }
  }
  
  public function map($httpMethod,$url,$methodName){
    $this->mappings[] = compact('httpMethod','url','methodName');
  }
  
  public function get($url,$methodName){
    $this->map('GET',$url,$methodName);
  }
  
  public function post($url,$methodName){
    $this->map('POST',$url,$methodName);
  }
  
  public function put($url,$methodName){
    $this->map('PUT',$url,$methodName);
  }
  
  public function options($url,$methodName){
    $this->map('OPTIONS',$url,$methodName);
  }
  
  public function delete($url,$methodName){
    $this->map('DELETE',$url,$methodName);
  }
  
}

class SessionWrapper extends ArrayIterator {
  
  public $name;
  public $id;
  
  public function __construct($id=null,$name=null){
    $this->id = $id;
    $this->name = $name;
  }
  
  public function open() {
    if (!is_null($this->id)) session_id($this->id);
    if (!is_null($this->name)) session_name($this->name);
    session_start();
    $this->id = session_id();
    $this->name = session_name();
  }
  
  public function close() {
    session_write_close();
  }
  
  public function destroy() {
    setcookie($this->name,null,time()-86400);
    session_unset();
    session_destroy();
  }
  
  public function __get($key) {
    global $_SESSION;
    return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
  }
  
  public function __set($key, $value) {
    global $_SESSION;
    $_SESSION[$key] = $value;
    return $value;
  }
  
  public function count() {
    return count($_SESSION);
  }
  
  public function rewind() {
    return reset($_SESSION);
  }
  
  public function current() {
    return current($_SESSION);
  }
  
  public function key() {
    return key($_SESSION);
  }
  
  public function next() {
    return next($_SESSION);
  }
  
  public function valid() {
    return key($_SESSION) !== null;
  }
  
  public function check($key) {
    global $_SESSION;
    return isset($_SESSION[$key]);
  }
  
}

class RequestWrapper extends ArrayIterator {
  
  public function __construct(){
    $this->_parseParams();
  }
  
  public function __get($key) {
    global $_REQUEST;
    return isset($_REQUEST[$key]) ? $_REQUEST[$key] : null;
  }
  
  public function __set($key, $value) {
    global $_REQUEST;
    $_REQUEST[$key] = $value;
    return $value;
  }
  
  private function _parseParams() {
    $method = $_SERVER['REQUEST_METHOD'];
    if ($method == 'PUT' || $method == 'DELETE') {
      parse_str(file_get_contents('php://input'), $params);
      $GLOBALS["_{$method}"] = $params;
      // Add these request vars into _REQUEST, mimicing default behavior, PUT/DELETE will override existing COOKIE/GET vars
      $_REQUEST = $params + $_REQUEST;
    }
  }
  
  public function count() {
    return count($_REQUEST);
  }
  
  public function rewind() {
    return reset($_REQUEST);
  }
  
  public function current() {
    return current($_REQUEST);
  }
  
  public function key() {
    return key($_REQUEST);
  }
  
  public function next() {
    return next($_REQUEST);
  }
  
  public function valid() {
    return key($_REQUEST) !== null;
  }
  
  public function check($key) {
    global $_REQUEST;
    return isset($_REQUEST[$key]);
  }
  
}

class MultiSort {
  
  public function byKeyLength($array,$key,$asc=false) {
    $result = array();
    $values = array();
    foreach ($array as $id => $value) {
      $values[$id] = isset($value[$key]) ? $value[$key] : '';
    }
    $func = ($asc) ? 'len' : 'rlen';
    uasort($values,array($this,$func));
    foreach ($values as $key => $value) {
      $result[$key] = $array[$key];
    }
    return $result;
  }
  
  public function len($a,$b){
    $diff = strlen($a)-strlen($b);
    return ($diff<=0) ? -1 : 1;
  }
  
  public function rlen($a,$b){
    $diff = strlen($b)-strlen($a);
    return ($diff<=0) ? -1 : 1;
  }
  
}

class ArrayWrapper {
  
  private $subject;
  
  public function __construct(&$subject) {
    $this->subject = $subject;
  }
  
  public function __get($key) {
    return isset($this->subject[$key]) ? $this->subject[$key] : null;
  }
  
  public function __set($key, $value) {
    return $this->subject = $value;
  }
  
}


class Security {
  
  public $salt1;
  public $salt2;
  
  public function __construct($salt1=null,$salt2=null){
    $this->salt1 = isset($salt1) ? $salt1 : 'i$16#&#ssdg^436&';
    $this->salt2 = isset($salt2) ? $salt2 : 'x%37aa@!gsdxyEss';
  }
  
  public function hash($string) {
    // salts
    $salt1 = sha1($string.$this->salt1);
    $salt1 = substr($salt1,26);
    $salt2 = sha1($string.$this->salt2);
    $salt2 = substr($salt2,35);
    // hash
    $hash = sha1("$salt1$string$salt2");
    return $hash;
  }
  
  public function escape_mysql($x=null) {
    if(!isset($x)) return null;
    else if(is_string($x)) return mysql_real_escape_string($x);
    else if(is_array($x)) {
      foreach($x as $k=>$v) {
        $k2=mysql_real_escape_string($k);
        if($k!=$k2) unset($x[$k]);
        $x[$k2]=self::escape_mysql($v);
      }
      return $x;
    }
  }
  
  public function escape_shellarg($x=null) {
    if(!isset($x)) return null;
    else if(is_string($x)) return escapeshellarg($x);
    else if(is_array($x)) {
      foreach($x as $k=>$v) {
        $k2=escapeshellarg($k);
        if($k!=$k2) unset($x[$k]);
        $x[$k2]=self::escape_shellarg($v);
      }
      return $x;
    }
  }
  
  public function escape_shellcmd($x=null) {
    if(!isset($x)) return null;
    else if(is_string($x)) return escapeshellcmd($x);
    else if(is_array($x)) {
      foreach($x as $k=>$v) {
        $k2=escapeshellcmd($k);
        if($k!=$k2) unset($x[$k]);
        $x[$k2]=self::escape_shellcmd($v);
      }
      return $x;
    }
  }
  
  public function validateEmail($email) {
    return preg_match('/^[^@\[\];:,<>\(\)]+@[^@\[\];,<>\(\)]+\.[^@\[\];:,<>\(\)]{2}.*$/i',$email);
  }
  
  public function clientIP() {
    $ip;
    if (getenv('HTTP_CLIENT_IP'))
      $ip = getenv('HTTP_CLIENT_IP');
    else if(getenv('HTTP_X_FORWARDED_FOR'))
      $ip = getenv('HTTP_X_FORWARDED_FOR');
    else if(getenv('REMOTE_ADDR'))
      $ip = getenv('REMOTE_ADDR');
    else
      $ip = false;
    return $ip;
  }
  
  public function blacklistCheck($ip) {
    $dnsbl_check=array('bl.spamcop.net','list.dsbl.org','sbl.spamhaus.org','xbl.spamhaus.org');
    if($ip){
      $rip=implode('.',array_reverse(explode(".",$ip)));
      foreach($dnsbl_check as $val){
        return (checkdnsrr($rip.'.'.$val.'.','A')) ? true : false;
      }
    }
    return false;
  }
  
  public function bitMask($mask=0) {
    if(!is_numeric($mask)) return array();
    $return = array(0);
    while ($mask > 0) {
      for($i = 0, $n = 0; $i <= $mask; $i = 1 * pow(2, $n), $n++) {
        $end = $i;
      }
      $return[] = $end;
      $mask = $mask - $end;
    }
    sort($return);
    return $return;
  }
  
}

class Log {
  
  private $log_file;
  private $fp = null;
  
  public function __construct($path){
    $this->log_file = $path;
  }
  
  // write message to the log file
  public function message($message){
    // if file pointer doesn't exist, then open log file
    if (!$this->fp) $this->open_file();
    // define script name
    $uri = $_SERVER['REDIRECT_URL'];
    // client ip
    $ip = Security::clientIP();
    // define current time
    $time = date('H:i:s');
    // write current time, script name and message to the log file
    fwrite($this->fp, "$time -- $uri -- $ip -- $message\n");
  }
  
  // open log file
  private function open_file(){
    // define log file path and name
    $lfile = $this->log_file;
    // define the current date (it will be appended to the log file name)
    $today = date('Y-m-d');
    // open log file for writing only; place the file pointer at the end of the file
    // if the file does not exist, attempt to create it
    $this->fp = fopen($lfile.'.'.$today.'.log', 'a') or exit("Can't open $lfile!");
  }
  
}

?>