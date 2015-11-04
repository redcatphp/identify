 Identify
=========

 Identify is a complete authentication system with session management and cryptographic libraries. It including many third-party library.

Session
-------

 The surikat session handler is independent from native php session and use a strong random id cookie which is regenerated when *$cookieLifetime* expire. Unlike native php session it allow you to use a session over any length you want, like one year for example, and it integrate an anti-bruteforce system with attempts records based on hashed ip. 
```php
$name = 'redcat';  
$cookieLifetime = 3600; // 1 hour  
$sessionLifetime = 43200;  // 1 year  
$session = new \\RedCat\\Identify\\Session($name,$cookieLifetime,$sessionLifetime);  
if(isset($session['var']))  
    var\_dump( $session['var'] );  
$session['var'] = 'value';  
            
```


Auth
----

Here is the main authentication API which you can use with Auth class.

### login

 
```php
$auth->login($login, $password, $lifetime=0);  
            
```


### loginRoot

 
```php
$auth->loginRoot($password,$lifetime=0);  
            
```


### loginPersona

 
```php
$auth->loginPersona($email,$lifetime=0);  
            
```


### register

 
```php
$auth->register($email, $login, $password, $repeatpassword, $name=null);  
            
```


### activate

 
```php
$auth->activate($key);  
            
```


### requestReset

 
```php
$auth->requestReset($email);  
            
```


### logout

 
```php
$auth->logout();  
            
```


### getHash

 
```php
$auth->getHash($string, $salt);  
            
```


### getUID

 
```php
$auth->getUID($login);  
            
```


### getUser

 
```php
$auth->getUser($uid);  
            
```


### deleteUser

 
```php
$auth->deleteUser($uid, $password);  
            
```


### validateLogin

 
```php
$auth->validateLogin($login);  
            
```


### validateDisplayname

 
```php
$auth->validateDisplayname($login);  
            
```


### resetPass

 
```php
$auth->resetPass($key, $password, $repeatpassword);  
            
```


### resendActivation

 
```php
$auth->resendActivation($email);  
            
```


### changePassword

 
```php
$auth->changePassword($uid, $currpass, $newpass, $repeatnewpass);  
            
```


### getEmail

 
```php
$auth->getEmail($uid);  
            
```


### changeEmail

 
```php
$auth->changeEmail($uid, $email, $password);  
            
```


### getRight

 
```php
$auth->getRight();  
            
```


### setRight

 
```php
$auth->setRight($r);  
            
```


### connected

 
```php
$auth->connected();  
            
```


### allowed

 
```php
$auth->allowed($d);  
            
```


### allow

 
```php
$auth->allow($d);  
            
```


### deny

 
```php
$auth->deny($d);  
            
```


### lock

 
```php
$auth->lock($r,$redirect=true);  
            
```


AuthServer
----------

 First parameter correspond to *RedCat\\Identify\\Auth* rights constants. You can use them directly, or if you use string (like in example) it will be automaticaly converted to corresponding constant. The rights constants are Auth::RIGHT\_MANAGE, Auth::RIGHT\_EDIT, Auth::RIGHT\_MODERATE, Auth::RIGHT\_POST.  
 The second parameter (true by default) is for enable GET redirection to avoid re-POST on refresh. 
```php
$authServer = new \\RedCat\\Identify\\AuthServer;  
$authServer->htmlLock('RIGHT\_MANAGE',true);  
            
```
 Following example is for use inside a code (off course with [ob-implicit-flush](http://php.net/manual/en/function.ob-implicit-flush.php) setted to false). It will handle authentication process, from locking with authentication window to logout button ouput. Put the code where you want button to appear. 
```php
$authServer->lougoutBTN();  
            
```
 For handle signup and login process: 
```php
$authServer->action();  
            
```
 For get identity: 
```php
$session = $authServer->getSession();  
$identity = $session['\_AUTH\_'];  
            
```
 For handle reset password request: 
```php
$authServer->resetreq();  
            
```
 For handle reset password confirmation: 
```php
$authServer->resetpass();  
            
```
 For logout: 
```php
$authServer->getAuth()->logout()  
            
```
 And, in any context, to get result message: 
```php
echo $authServer->getResultMessage(true);  
            
```


PHPMailer
---------

 PHPMailer - A full-featured email creation and transfer class for PHP.  
 PHPMailer is a third party toolbox. See the official [PHPMailer](https://github.com/PHPMailer/PHPMailer) and [examples](https://github.com/PHPMailer/PHPMailer/tree/master/examples). There is simple facade class in *RedCat\\Identify* namespace for use PHPMailer in simplicity:  
 
```php
$mailer = new RedCat\\Identify\\PHPMailer(  
    $fromEmail,$fromName,  
    $replyEmail,$replyName,  
    $host,$port,$username,$passowrd,$secure,  
    $sendmail,  
    $debug,$exceptions  
);  
$mailer->mail($email, $subject, $message, $html=true);  
            
```


RandomLib
---------

 RandomLib - A library for generating random numbers and strings.  
 RandomLib is a third party toolbox. See the official [RandomLib](https://github.com/ircmaxell/RandomLib) 


SecurityLib
-----------

 SecurityLib is a third party toolbox (dependency of RandomLib). See the official [SecurityLib](https://github.com/ircmaxell/SecurityLib)

PhpSecLib
---------

 PhpSecLib - PHP Secure Communications Library.  
 PhpSecLib is a third party cryptography toolbox. See the official [PhpSecLib](https://github.com/phpseclib/phpseclib) 
