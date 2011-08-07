<?php
/**
 * This is an example Endgame app you can build off of or use for reference.
 * 
 * Proper documentation pending... please bear with me.
 *
 */
 
class App extends Endgame {
  
  public function __construct($config=array()){
    parent::__construct($config);
  }
  
  # Example Methods (associated resource mappings below)
  // Simple JSON Example
  public function jsonExample($params) {
    $this->auth(PERMIT_SYSTEM_USERS) or $this->deny();
    $this->output['data'] = $params;
    $this->send();
  }
  // Simple XML Example
  public function xmlExample($params){
    $this->auth(PERMIT_SYSTEM_USERS) or $this->deny();
    $this->throttle(10); // custom method throttle example, 10 reqs / min -- note that this will run in addition to the global throttle
    $this->output['data'] = $params;
    $this->send('200','xml');
  }
  // File Download Example
  public function fileExample($params){
    $this->auth(PERMIT_SYSTEM_USERS) or $this->deny();
    extract($params);
    $this->sendFile('result.jpg','image/jpeg',getenv('DOCUMENT_ROOT').'/resources/images/'.$filename.'.jpg');
  }
  // Basic Templating Example
  public function viewExample(){
    $this->output['message'] = 'This is an example!';
    $this->render('example');
  }
  
  # Example Registration Methods
  public function registerUser(){
    $this->register();
    $this->send();
  }
  
  public function registerSuper(){
    // you can comment out the authentication line below and register yourself as a super user if you're just getting things setup but remember to remove the comment when you're done (or remove this method entirely if you'll be the only super user)
    $this->auth(PERMIT_SUPER) or $this->deny();
    $this->register(0);
    $this->send();
  }
  
}


# Create App
$app = new App($config);


# Example Resource Mappings (associated methods above)
$app->get('/json-example/:param1','jsonExample');
$app->get('/xml-example/:param1/:param2/:param3','xmlExample');
$app->get('/jpg/:filename','fileExample');
$app->get('/view-example','viewExample');

# Example Registration Mappings
$app->post('/register','registerUser');
$app->post('/register-super','registerSuper');

# ...and GO!
$app->run();


/* ***************************************************************************

A NOTE ABOUT API TESTING WITH CURL

For HTTP Authentication to work, you'll need to setup a .netrc
file in your home folder. Here's what to put in the .netrc file:

machine api.getstashe.com
login your@email.com
password YoUrPaSsWoRd

You won't be able to test any of the authenticated mappings unless you complete
the above step FIRST. Once that's done, you can test everything to your hearts
delight.

Here are some examples:

curl -nX OPTIONS http://localhost/resource/
curl -nX GET "http://localhost/resource/?someparam=val1&someotherparam=val2"
curl -nX PUT http://localhost/resource/ -d someparam=val1 -d someotherparam=val2
curl -nX POST http://localhost/resource/ -d someparam=val1 -d someotherparam=val2
curl -nX DELETE http://localhost/resource/ -d someparam=val1 -d someotherparam=val2


!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
UPDATED 2011-08-06
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Because of the lack of access to PHP_AUTH_USER and PHP_AUTH_PW on some server's
(because of PHP-CGI), I've added support for supplying login credentials as
request paramaters ('auth_user', 'auth_pw')

Here are the above examples again but this time using request parameters:

curl -X OPTIONS http://localhost/resource/ -d "auth_user=your@email.com" -d "auth_pw=YoUrPaSsWoRd"
curl -X GET "http://localhost/resource/?auth_user=your@email.com&auth_pw=YoUrPaSsWoRd&someparam=val1&someotherparam=val2"
curl -X PUT http://localhost/resource/ -d "auth_user=your@email.com" -d "auth_pw=YoUrPaSsWoRd" -d someparam=val1 -d someotherparam=val2
curl -X POST http://localhost/resource/ -d "auth_user=your@email.com" -d "auth_pw=YoUrPaSsWoRd" -d someparam=val1 -d someotherparam=val2
curl -X DELETE http://localhost/resource/ -d "auth_user=your@email.com" -d "auth_pw=YoUrPaSsWoRd" -d someparam=val1 -d someotherparam=val2

*************************************************************************** */

?>