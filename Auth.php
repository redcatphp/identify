<?php
/*
 * Auth - Complete Authentication System
 *
 * @package Identify
 * @version 1.4
 * @link http://github.com/redcatphp/Identify/
 * @author Jo Surikat <jo@surikat.pro>
 * @website http://redcatphp.com
 */
namespace RedCat\Identify;

use RedCat\Ding\Di;
use RedCat\DataMap\B;
use RedCat\DataMap\DataSource;
if (version_compare(phpversion(), '5.5.0', '<')){
	require_once __DIR__.'/password-compat.inc.php';
}
class Auth{
	
	const RIGHT_MANAGE = 2;
	const RIGHT_EDIT = 4;
	const RIGHT_MODERATE = 8;
	const RIGHT_POST = 16;
	
	const ROLE_ADMIN = 30;
	const ROLE_EDITOR = 4;
	const ROLE_MODERATOR = 8;
	const ROLE_MEMBER = 16;
	
	const ERROR_USER_BLOCKED = 1;
	const ERROR_USER_BLOCKED_2 = 46;
	const ERROR_USER_BLOCKED_3 = 47;
	const ERROR_LOGIN_SHORT = 2;
	const ERROR_LOGIN_LONG = 3;
	const ERROR_LOGIN_INCORRECT = 4;
	const ERROR_LOGIN_INVALID = 5;
	const ERROR_NAME_INVALID =  48;
	const ERROR_PASSWORD_SHORT = 6;
	const ERROR_PASSWORD_LONG = 7;
	const ERROR_PASSWORD_INVALID = 8;
	const ERROR_PASSWORD_NOMATCH = 9;
	const ERROR_PASSWORD_INCORRECT = 10;
	const ERROR_PASSWORD_NOTVALID = 11;
	const ERROR_NEWPASSWORD_SHORT = 12;
	const ERROR_NEWPASSWORD_LONG = 13;
	const ERROR_NEWPASSWORD_INVALID = 14;
	const ERROR_NEWPASSWORD_NOMATCH = 15;
	const ERROR_LOGIN_PASSWORD_INVALID = 16;
	const ERROR_LOGIN_PASSWORD_INCORRECT = 17;
	const ERROR_EMAIL_INVALID = 18;
	const ERROR_EMAIL_INCORRECT = 19;
	const ERROR_NEWEMAIL_MATCH = 20;
	const ERROR_ACCOUNT_INACTIVE = 21;
	const ERROR_SYSTEM_ERROR = 22;
	const ERROR_LOGIN_TAKEN = 23;
	const ERROR_EMAIL_TAKEN = 24;
	const ERROR_AUTHENTICATION_REQUIRED = 25;
	const ERROR_ALREADY_AUTHENTICATED = 26;
	const ERROR_RESETKEY_INVALID = 27;
	const ERROR_RESETKEY_INCORRECT = 28;
	const ERROR_RESETKEY_EXPIRED = 29;
	const ERROR_ACTIVEKEY_INVALID = 30;
	const ERROR_ACTIVEKEY_INCORRECT = 31;
	const ERROR_ACTIVEKEY_EXPIRED = 32;
	const ERROR_RESET_EXISTS = 33;
	const ERROR_ALREADY_ACTIVATED = 34;
	const ERROR_ACTIVATION_EXISTS = 35;
	const ERROR_UNABLE_SEND_ACTIVATION = 36;
	const ERROR_EMAIL_REGISTERING = 37;
	const OK = 100;
	const OK_PASSWORD_CHANGED = 101;
	const OK_EMAIL_CHANGED = 102;
	const OK_ACCOUNT_ACTIVATED = 103;
	const OK_ACCOUNT_DELETED = 104;
	const OK_LOGGED_IN = 105;
	const OK_LOGGED_OUT = 106;
	const OK_REGISTER_SUCCESS = 107;
	const OK_PASSWORD_RESET = 108;
	const OK_RESET_REQUESTED = 109;
	const OK_ACTIVATION_SENT = 110;
	const OK_ACCOUNT_ACTIVATED_AND_AUTOLOGGED = 111;

	public $siteUrl;
	private $db;
	private $right;
	protected $cost = 10;
	protected $Session;
	protected $Server;
	
	protected $rootLogin;
	protected $rootPassword;
	protected $rootEmail;
	protected $rootName;
	protected $siteLoginUri;
	protected $siteActivateUri;
	protected $siteResetUri;
	protected $tableUsers;
	protected $tableRequests;
	protected $algo;
	protected $mailActivationSubject;
	protected $mailActivationTemplate;
	protected $mailResetSubject;
	protected $mailResetTemplate;
	
	protected $rootPasswordNeedRehash;
	protected $di;
	
	protected $baseHref;
	protected $suffixHref;
	protected $server;
	
	function __construct(Session $Session=null,
		$rootLogin = 'root',
		$rootPassword = null,
		$rootName	= 'Developer',
		$rootEmail	= null,
		$siteLoginUri = 'auth/login',
		$siteActivateUri = 'auth/signin',
		$siteResetUri ='auth/reset',
		$tableUsers = 'user',
		$tableRequests = 'request',
		$algo = PASSWORD_DEFAULT,
		DataSource $db = null,
		Di $di = null,
		$mailActivationSubject='Account Activation',
		$mailActivationTemplate=null,
		$mailResetSubject='Password reset request',
		$mailResetTemplate=null,
		$server=null
	){
		$this->rootLogin = $rootLogin;
		$this->rootPassword = $rootPassword;
		$this->rootEmail = $rootEmail;
		$this->rootName = $rootName;
		$this->siteLoginUri = $siteLoginUri;
		$this->siteActivateUri = $siteActivateUri;
		$this->siteResetUri = $siteResetUri;
		$this->tableUsers = $tableUsers;
		$this->tableRequests = $tableRequests;
		$this->algo = $algo;
		$this->mailActivationSubject = $mailActivationSubject;
		$this->mailActivationTemplate = $mailActivationTemplate;
		$this->mailResetSubject = $mailResetSubject;
		$this->mailResetTemplate = $mailResetTemplate;
		
		if(!$Session)
			$Session = new Session();
		$this->Session = $Session;
		if(!isset($db)){
			$this->db = B::getDatabase();
		}
		
		if(!$server)
			$server = &$_SERVER;
		$this->server = $server;

		$this->siteUrl = $this->getBaseHref();
		$this->siteUrl = rtrim($this->siteUrl,'/').'/';
		$this->di = $di;
	}
	function getSession(){
		return $this->Session;
	}
	function rootPasswordNeedRehash(){
		return $this->rootPasswordNeedRehash;
	}
	function sendMail($email, $type, $key, $login){
		if($type=='activation'){
			$subject = $this->mailActivationSubject;
			if($this->mailActivationTemplate)
				$message = includeOutput($this->mailActivationTemplate,['site'=>$this->siteUrl,'uri'=>$this->siteActivateUri,'key'=>$key]);
			else
				$message = "Account activation required : <strong><a href=\"{$this->siteUrl}{$this->siteActivateUri}?key={$key}\">Activate my account</a></strong>";
		}
		else{
			$subject = $this->mailResetSubject;
			if($this->mailResetTemplate)
				$message = includeOutput($this->mailResetTemplate,['site'=>$this->siteUrl,'uri'=>$this->siteResetUri,'key'=>$key]);
			else
				$message = "Password reset request : <strong><a href=\"{$this->siteUrl}{$this->siteResetUri}?key={$key}\">Reset my password</a></strong>";
		}
		$mailer = $this->di->create(PHPMailer::class);
		return $mailer->mail([$email=>$login],$subject,$message);
	}
	function loginRoot($password,$lifetime=0){
		$pass = $this->rootPassword;
		if(!$pass)
			return self::ERROR_SYSTEM_ERROR;
		$id = 0;
		if(strpos($pass,'$')!==0){
			if($pass!=$password){
				$this->Session->addAttempt();
				return self::ERROR_LOGIN_PASSWORD_INCORRECT;
			}
		}
		else{
			if(!($password&&password_verify($password, $pass))){
				$this->Session->addAttempt();
				return self::ERROR_LOGIN_PASSWORD_INCORRECT;
			}
			else{
				$options = ['cost' => $this->cost];
				if(password_needs_rehash($pass, $this->algo, $options)){
					$this->rootPassword = password_hash($password, $this->algo, $options);
					$this->rootPasswordNeedRehash = true;
				}
			}
		}
		if($this->db){
			if($this->db[$this->tableUsers]->exists()){
				if($this->rootEmail)
					$id = $this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE login = ?',[$this->rootLogin]);
				else
					$id = $this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE login = ? OR email = ?',[$this->rootLogin,$this->rootEmail]);
			}
			else
				$id = null;
			if(!$id){
				try{
					$user = $this->db
						->create($this->tableUsers,[
							'login'=>$this->rootLogin,
							'name'=>isset($this->rootName)?$this->rootName:$this->rootLogin,
							'email'=>isset($this->rootEmail)?$this->rootEmail:null,
							'active'=>1,
							'right'=>static::ROLE_ADMIN,
							'type'=>'root'
						])
					;
					$id = $user->id;
				}
				catch(\Exception $e){
					return self::ERROR_SYSTEM_ERROR;
				}
			}
		}
		$this->addSession((object)[
			'id'=>$id,
			'login'=>$this->rootLogin,
			'name'=>isset($this->rootName)?$this->rootName:$this->rootLogin,
			'email'=>isset($this->rootEmail)?$this->rootEmail:null,
			'right'=>static::ROLE_ADMIN,
			'type'=>'root'
		],$lifetime);
		return self::OK_LOGGED_IN;
	}
	function loginPersona($email,$lifetime=0){
		if($e=$this->validateEmail($email))
			return $e;
		$userDefault = [
			'login'=>$email,
			'name'=>$email,
			'email'=>$email,
			'type'=>'persona',
			'right'=>self::ROLE_MEMBER,
			'active'=>1,
		];
		if($this->db){
			$user = $this->db->findOne($this->tableUsers,' email = ? AND type = ?',[$email,'persona']);
			if(!$user){
				try{
					$user = $this->db->create($this->tableUsers,$userDefault);
				}
				catch(\Exception $e){
					return self::ERROR_SYSTEM_ERROR;
				}
			}
		}
		else{
			$user = $userDefault;
			$user->id = $email;
		}
		$this->addSession($user,$lifetime);
		return self::OK_LOGGED_IN;
	}
	function login($login, $password, $lifetime=0){
		if($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($login==$this->rootLogin||($this->rootEmail&&$login==$this->rootEmail)&&$this->rootPassword)
			return $this->loginRoot($password,$lifetime);
		$loginIsEmail = !ctype_alnum($login)&&filter_var($login,FILTER_VALIDATE_EMAIL);
		if(!$loginIsEmail&&$this->validateLogin($login)){
			$this->Session->addAttempt();
			return self::ERROR_LOGIN_PASSWORD_INVALID;
		}
		if($this->validatePassword($password)){
			$this->Session->addAttempt();
			return self::ERROR_LOGIN_PASSWORD_INVALID;
		}
		
		$col = $loginIsEmail?'email':'login';
		
		$user = null;
		if($this->db[$this->tableUsers]->exists()){
			 $user = $this->db[$this->tableUsers]->getClone()->where($col.' = ?',[$login])->getRow();
		}
		if(!$user){
			$this->Session->addAttempt();
			return self::ERROR_LOGIN_PASSWORD_INCORRECT;
		}
		
		if(!($password&&password_verify($password, $user->password))){
			$this->Session->addAttempt();
			return self::ERROR_LOGIN_PASSWORD_INCORRECT;
		}
		else{
			$options = ['cost' => $this->cost];
			if(password_needs_rehash($user->password, $this->algo, $options)){
				$password = password_hash($password, $this->algo, $options);
				$row = $this->db->read($this->tableUsers,(int)$user->id);
				$row->password = $password;
				try{
					$this->db->put($row);
				}
				catch(\Exception $e){
					return self::ERROR_SYSTEM_ERROR;
				}
			}
		}
		if(!isset($user->active)||$user->active!=1){
			$this->Session->addAttempt();
			return self::ERROR_ACCOUNT_INACTIVE;
		}
		if(!$this->addSession($user,$lifetime)){
			return self::ERROR_SYSTEM_ERROR;
		}
		return self::OK_LOGGED_IN;
	}

	function register($email, $login, $password, $repeatpassword, $name=null){
		ob_start();
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validateEmail($email))
			return $e;
		if($login&&($e=$this->validateLogin($login)))
			return $e;
		if($name&&($e=$this->validateDisplayname($name)))
			return $e;
		if($e=$this->validatePassword($password))
			return $e;
		if($password!==$repeatpassword){
			return self::ERROR_PASSWORD_NOMATCH;
		}
		if($this->isEmailRegistering($email)){
			return self::ERROR_EMAIL_REGISTERING;
		}
		if($this->isEmailTaken($email)){
			$this->Session->addAttempt();
			return self::ERROR_EMAIL_TAKEN;
		}
		if($login&&$this->isLoginTaken($login)){
			$this->Session->addAttempt();
			return self::ERROR_LOGIN_TAKEN;
		}
		if(self::ERROR_SYSTEM_ERROR===$this->addUser($email, $password, $login, $name))
			return self::ERROR_UNABLE_SEND_ACTIVATION;
		return self::OK_REGISTER_SUCCESS;
	}
	function activate($key,$autologin=false,$lifetime=0){
		if($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		$getRequest = $this->getRequest($key, 'activation');
		if(!is_object($getRequest))
			return self::ERROR_ACTIVEKEY_INVALID;
		$user = $this->getUser($getRequest->{$this->tableUsers.'_id'});
		if(isset($user->active)&&$user->active==1){
			$this->Session->addAttempt();
			$this->deleteRequest($getRequest->id);
			return self::ERROR_SYSTEM_ERROR;
		}
		$row = $this->db->read($this->tableUsers,(int)$getRequest->{$this->tableUsers.'_id'});
		$row->active = 1;
		$this->db->put($row);
		$this->deleteRequest($getRequest->id);
		if($autologin){
			if(!$this->addSession($user,$lifetime)){
				return self::ERROR_SYSTEM_ERROR;
			}
			return self::OK_ACCOUNT_ACTIVATED_AND_AUTOLOGGED;
		}
		return self::OK_ACCOUNT_ACTIVATED;
	}
	function requestReset($email){
		ob_start();
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validateEmail($email))
			return $e;
		if($this->db[$this->tableUsers]->exists())
			$id = $this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE email = ?',[$email]);
		else
			$id = null;
		if(!$id){
			$this->Session->addAttempt();
			return self::ERROR_EMAIL_INCORRECT;
		}
		if($e=$this->addRequest($id, $email, 'reset')){
			$this->Session->addAttempt();
			return $e;
		}
		return self::OK_RESET_REQUESTED;
	}
	function logout(){
		if($this->connected()&&$this->Session->destroy()){
			return self::OK_LOGGED_OUT;
		}
	}
	function getHash($string){
		return password_hash($string, $this->algo, ['cost' => $this->cost]);
	}
	private function addSession($user,$lifetime=0){
		$this->Session->setCookieLifetime($lifetime);
		$this->Session->setKey($user->id);
		$auth = [];
		foreach($user as $k=>$v){
			if($k!='password')
				$auth[$k] = $v;
		}
		$this->Session->set('_AUTH_',$auth);
		return true;
	}
	private function isEmailRegistering($email){
		if($this->db[$this->tableUsers]->exists())
			return (bool)$this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE email = ? AND active < 1',[$email]);
	}
	private function isEmailTaken($email){
		if($this->db[$this->tableUsers]->exists())
			return (bool)$this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE email = ?',[$email]);
	}
	private function isLoginTaken($login){
		if($this->db[$this->tableUsers]->exists())
			 return (bool)$this->db->getCell('SELECT id FROM '.$this->db->escTable($this->tableUsers).' WHERE login = ?',[$login]);
	}
	private function addUser($email, $password, $login=null, $name=null){
		$password = $this->getHash($password);
		try{
			$row = $this->db->create($this->tableUsers,[				
				'login' => $login,
				'name' => $name,
				'email' => $email,
				'password' => $password,
				'right' => self::ROLE_MEMBER,
				'type' => 'local',
				'active' => 0,
			]);
		}
		catch(\Exception $e){
			return self::ERROR_SYSTEM_ERROR;
		}
		$uid = $row->id;
		if(self::ERROR_SYSTEM_ERROR===$e=$this->addRequest($uid, $email, 'activation')){
			$this->db->delete($row);
			return $e;
		}
	}

	function getUser($uid){
		return $this->db->read($this->tableUsers,(int)$uid);
	}

	function deleteUser($uid, $password){
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validatePassword($password)){
			$this->Session->addAttempt();
			return $e;
		}
		$getUser = $this->getUser($uid);
		if(!($password&&password_verify($password, $getUser['password']))){
			$this->Session->addAttempt();
			return self::ERROR_PASSWORD_INCORRECT;
		}
		$row = $this->db->read($this->tableUsers,(int)$uid);
		if(!$this->db->delete($row)){
			return self::ERROR_SYSTEM_ERROR;
		}
		$this->Session->destroyKey($uid);
		foreach($this->db->one2many($row,$this->tableRequests) as $request){
			if(!$this->db->delete($request)){
				return self::ERROR_SYSTEM_ERROR;
			}
		}		
		return self::OK_ACCOUNT_DELETED;
	}
	private function addRequest($uid, $email, $type){
		$row = $this->db->findOne($this->tableRequests,$this->db->esc($this->tableUsers.'_id').' = ? AND type = ?',[$uid, $type]);
		if($row){
			$this->deleteRequest($row->id);
		}
		$user = $this->getUser($uid);
		if($type == 'activation' && isset($user->active) && $user->active == 1){
			return self::ERROR_ALREADY_ACTIVATED;
		}
		$key = Random::getString(40);
		$expire = date("Y-m-d H:i:s", strtotime("+1 day"));
		$request = [
			'_type'=>$this->tableRequests,
			'_one_'.$this->tableUsers.'_x_'=>$user,
			'rkey'=>$key,
			'expire'=>$expire,
			'type'=>$type
		];
		try{
			$this->db->put($request);
		}
		catch(\Exception $e){
			return self::ERROR_SYSTEM_ERROR;
		}
		
		$this->postProcess(function()use($email, $type, $key, $user){
			$this->sendMail($email, $type, $key, isset($user->name)?$user->name:null);
		});
	}
	private function postProcess($callback){
		if($this->debug){
			register_shutdown_function($callback);
			return;
		}
		
		header("Content-Encoding: none");
		header("Connection: close");
		register_shutdown_function(function()use($callback){			
			$size = ob_get_length();
			header("Content-Length: {$size}");
			ob_end_flush();
			ob_flush();
			flush();
			
			call_user_func($callback);
		});
	}
	private function getRequest($key, $type){
		$row = $this->db->findOne($this->tableRequests,' rkey = ? AND type = ?',[$key, $type]);
		if(!$row){
			$this->Session->addAttempt();
			if($type=='activation')
				return self::ERROR_ACTIVEKEY_INCORRECT;
			elseif($type=='reset')
				return self::ERROR_RESETKEY_INCORRECT;
			return;
		}
		$expiredate = strtotime($row->expire);
		$currentdate = strtotime(date("Y-m-d H:i:s"));
		if ($currentdate > $expiredate){
			$this->Session->addAttempt();
			$this->deleteRequest($row->id);
			if($type=='activation')
				return self::ERROR_ACTIVEKEY_EXPIRED;
			elseif($type=='reset')
				return self::ERROR_ACTIVEKEY_EXPIRED;
		}
		return $row;
	}
	private function deleteRequest($id){
		return $this->db->execute('DELETE FROM '.$this->db->escTable($this->tableRequests).' WHERE id = ?',[$id]);
	}
	function validateLogin($login){
		if (strlen($login) < 1)
			return self::ERROR_LOGIN_SHORT;
		elseif (strlen($login) > 30)
			return self::ERROR_LOGIN_LONG;
		elseif(!ctype_alnum($login)&&!filter_var($login, FILTER_VALIDATE_EMAIL))
			return self::ERROR_LOGIN_INVALID;
	}
	function validateDisplayname($login){
		if (strlen($login) < 1)
			return self::ERROR_NAME_INVALID;
		elseif (strlen($login) > 50)
			return self::ERROR_NAME_INVALID;
	}
	private function validatePassword($password){
		if (strlen($password) < 6)
			return self::ERROR_PASSWORD_SHORT;
		elseif (strlen($password) > 72)
			return self::ERROR_PASSWORD_LONG;
		elseif ((!preg_match('@[A-Z]@', $password) && !preg_match('@[a-z]@', $password)) || !preg_match('@[0-9]@', $password))
			return self::ERROR_PASSWORD_INVALID;
	}
	private function validateEmail($email){
		if (!filter_var($email, FILTER_VALIDATE_EMAIL))
			return self::ERROR_EMAIL_INVALID;
	}
	function resetPass($key, $password, $repeatpassword){
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validatePassword($password))
			return $e;
		if($password !== $repeatpassword){ // Passwords don't match
			return self::ERROR_NEWPASSWORD_NOMATCH;
		}
		$data = $this->getRequest($key, 'reset');
		if(empty($data))
			return self::ERROR_RESETKEY_INVALID;
			
		$user = $this->getUser($data[$this->tableUsers.'_id']);
		if(!$user){
			$this->Session->addAttempt();
			$this->deleteRequest($data['id']);
			return self::ERROR_SYSTEM_ERROR;
		}
		if(!($password&&password_verify($password, $user->password))){
			$password = $this->getHash($password);
			$row = $this->db->read($this->tableUsers,$data[$this->tableUsers.'_id']);
			$row->password = $password;
			try{
				$this->db->put($row);
			}
			catch(\Exception $e){
				return self::ERROR_SYSTEM_ERROR;
			}
		}
		$this->deleteRequest($data['id']);
		return self::OK_PASSWORD_RESET;
	}
	function resendActivation($email){
		ob_start();
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validateEmail($email))
			return $r;
		$row = $this->db->findOne($this->tableUsers,' email = ?',[$email]);
		if(!$row){
			$this->Session->addAttempt();
			return self::ERROR_EMAIL_INCORRECT;
		}
		if(isset($row->active)&&$row->active == 1){
			$this->Session->addAttempt();
			return self::ERROR_ALREADY_ACTIVATED;
		}
		if($e=$this->addRequest($row->id, $email, "activation")){
			$this->Session->addAttempt();
			return $e;
		}
		return self::OK_ACTIVATION_SENT;
	}
	function changePassword($uid, $currpass, $newpass, $repeatnewpass){
		if ($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validatePassword($currpass)){
			$this->Session->addAttempt();
			return $e;
		}
		if($e=$this->validatePassword($newpass))
			return $e;
		if($newpass !== $repeatnewpass){
			return self::ERROR_NEWPASSWORD_NOMATCH;
		}
		$user = $this->getUser($uid);
		if(!$user){
			$this->Session->addAttempt();
			return self::ERROR_SYSTEM_ERROR;
		}
		$newpass = $this->getHash($newpass);
		if(!($password&&password_verify($currpass, $user->password))){
			$this->Session->addAttempt();
			return self::ERROR_PASSWORD_INCORRECT;
		}
		if($currpass != $newpass){			
			$row = $this->db->read($this->tableUsers,(int)$uid);
			$row->password = $newpass;
			$this->db->put($row);
		}
		return self::OK_PASSWORD_CHANGED;
	}
	function getEmail($uid){
		$row = $this->db->read($this->tableUsers,(int)$uid);
		if (!$row->id){
			return false;
		}
		return $row->email;
	}
	function changeEmail($uid, $email, $password){
		if($s=$this->Session->isBlocked()){
			return [self::ERROR_USER_BLOCKED,$s];
		}
		if($e=$this->validateEmail($email))
			return $e;
		if($e=$this->validatePassword($password))
			return $e;
		$user = $this->getUser($uid);
		if(!$user){
			$this->Session->addAttempt();
			return self::ERROR_SYSTEM_ERROR;
		}
		if(!($password&&password_verify($password, $user->password))){
			$this->Session->addAttempt();
			return self::ERROR_PASSWORD_INCORRECT;
		}
		if ($email == $user->email){
			$this->Session->addAttempt();
			return self::ERROR_NEWEMAIL_MATCH;
		}
		$row = $this->db->read($this->tableUsers,(int)$uid);
		$row->email = $email;
		try{
			$this->db->put($row);
		}
		catch(\Exception $e){
			return self::ERROR_SYSTEM_ERROR;
		}
		return self::OK_EMAIL_CHANGED;
	}
	
	function setBaseHref($href){
		$this->baseHref = $href;
	}
	function getServerHttps(){
		return isset($this->server['HTTPS'])?$this->server['HTTPS']:null;
	}
	function getServerPort(){
		return isset($this->server['SERVER_PORT'])?$this->server['SERVER_PORT']:null;
	}
	function getProtocolHref(){
		return 'http'.($this->getServerHttps()=="on"?'s':'').'://';
	}
	function getServerHref(){
		return isset($this->server['SERVER_NAME'])?$this->server['SERVER_NAME']:null;
	}
	function getPortHref(){
		$ssl = $this->getServerHttps()=="on";
		return $this->getServerPort()&&((!$ssl&&(int)$this->getServerPort()!=80)||($ssl&&(int)$this->getServerPort()!=443))?':'.$this->getServerPort():'';
	}
	function getBaseHref(){
		if(!isset($this->baseHref)){
			$this->setBaseHref($this->getProtocolHref().$this->getServerHref().$this->getPortHref().'/');
		}
		return $this->baseHref.$this->getSuffixHref();
	}
	function setSuffixHref($href){
		$this->suffixHref = $href;
	}
	function getSuffixHref(){
		if(!isset($this->suffixHref)){
			if(isset($this->server['REDCAT_URI'])){
				$this->suffixHref = ltrim($this->server['REDCAT_URI'],'/');				
			}
			else{
				$docRoot = $this->server['DOCUMENT_ROOT'].'/';
				//$docRoot = dirname($this->server['SCRIPT_FILENAME']).'/';
				if(defined('REDCAT_CWD'))
					$cwd = REDCAT_CWD;
				else
					$cwd = getcwd();
				if($docRoot!=$cwd&&strpos($cwd,$docRoot)===0)
					$this->suffixHref = substr($cwd,strlen($docRoot));
			}
		}
		return $this->suffixHref;
	}

	function getRight(){
		if(!isset($this->right))
			$this->right = $this->Session->get('_AUTH_','right');
		return $this->right;
	}
	function setRight($r){
		$this->right = $r;
	}
	
	function connected(){
		return !!$this->Session->get('_AUTH_');
	}
	function allowed($d){
		if(is_string($d)) $d = constant(__CLASS__.'::'.$d);
		return !!($d&$this->getRight());
	}
	function allow($d){
		if(is_string($d)) $d = constant(__CLASS__.'::'.$d);
		return $this->setRight($d|$this->getRight());
	}
	function deny($d){
		if(is_string($d)) $d = constant(__CLASS__.'::'.$d);
		return $this->setRight($d^$this->getRight());
	}
	
	function lock($r,$redirect=true){
		if($this->allowed($r))
			return;
		
		//nocache headers
		header("Expires: Mon, 26 Jul 1997 05:00:00 GMT" ); 
		header("Last-Modified: " . gmdate("D, d M Y H:i:s" ) . " GMT" );
		header("Pragma: no-cache");
		header("Cache-Control: no-cache");
		header("Expires: -1");
		header("Cache-Control: post-check=0, pre-check=0", false);
		header("Cache-Control: no-store, no-cache, must-revalidate");
		
		if($redirect){
			if($this->connected())
				$redirect = '401';
			if($redirect===true)
				$redirect = isset($this->siteLoginUri)?$this->siteLoginUri:'401';
			header('Location: '.$this->siteUrl.$redirect,false,302);
		}
		else{
			http_response_code(401);
		}
		exit;
	}
}

function includeOutput(){
	if(func_num_args()>1)
		extract(func_get_arg(1));
	ob_start();
	include REDCAT_CWD.func_get_arg(0);
	return ob_get_clean();
}