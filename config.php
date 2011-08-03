<?php

# Session Garbage Collection Settings
ini_set('session.gc_probability', 1); // there's a 1...
ini_set('session.gc_divisor', 100); // ...in 100 chance (1%) that garbage collection will run when a new session is created
ini_set('session.gc_maxlifetime', 1209600); // delete sessions that haven't been used in two weeks or longer
ini_set('session.cookie_lifetime', 2592000); // delete session cookie after one month (30 days) even if recently used

# Permissions Scheme
// set groups
define('PERMIT_SUPER', 0);
define('PERMIT_ADMIN', 1);
define('PERMIT_SYSUSER', 2);
define('PERMIT_ENDUSER', 4);
// ...a couple sums to make things easy
define('PERMIT_SYSTEM_USERS', 3); // SUPER + ADMIN + SYSUSER
define('PERMIT_ALL_USERS', 7); // SCHEME SUM
// ..and finally a few default values
define('DEFAULT_GROUP', 4); // used by Endgame::register()
define('DEFAULT_AUTH_PERMIT', 0); // used by Endgame::auth()
define('DEFAULT_LOGIN_PERMIT', 7); // used by Endgame:login()

$config = array(
  
  # name
  'app_name' => 'Endgame Example App',
  
  # log file location
  'endgame_log_path' => '/tmp/endgame_log', // .yyyy-mm-dd.log will be appended to whatever filename you set here
  
  # message for any stray visitors to the web root
  'root_message' => "Hi there friend! I think you're lost...", // this displays when someone visits the site root, change it to whatever your want
  
  # salts
  // Set these salts to whatever you'd like for added security BUT DO NOT CHANGE OR LOSE THESE ONCE IN PRODUCTION!!! REQUESTS WON'T AUTHENTICATE!
  'salt1' => 'sgTS4^E#@8fdds#2',
  'salt2' => '226@#ssydf%TFdf&',
  
  # db config
  'db_host' => 'localhost',
  'db_user' => 'your_db_user',
  'db_pass' => 'PaSsWoRd123',
  'db_name' => 'your_db_name',
  
  # authentication table config
  'auth_table' => 'users', // name of table with authentication credentials
  'auth_userfield' => 'email', // name of field containing usernames
  'auth_passfield' => 'password', // name of field containing password hashes
  'auth_groupfield' => 'group', // name of field containing group bit
  'auth_userfieldisemail' => true, // if true, username must be an email address
  
  # global throttle config
  'global_throttle_limit' => 100,
  'global_throttle_window' => 60
  
);

?>