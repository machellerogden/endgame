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
  
}


# Create App
$app = new App($config);


# Example Resource Mappings (associated methods above)
$app->get('/json-example/:param1','jsonExample');
$app->get('/xml-example/:param1/:param2/:param3','xmlExample');
$app->get('/jpg/:filename','fileExample');
$app->get('/view-example','viewExample');


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

  $ curl -nX OPTIONS http://localhost/resource/
  $ curl -nX GET "http://localhost/resource/?someparam=val1&someotherparam=val2"
  $ curl -nX PUT http://localhost/resource/ -d someparam=val1 -d someotherparam=val2
  $ curl -nX POST http://localhost/resource/ -d someparam=val1 -d someotherparam=val2
  $ curl -nX DELETE http://localhost/resource/ -d someparam=val1 -d someotherparam=val2
  
*************************************************************************** */


?>