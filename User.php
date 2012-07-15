<?php
/*
Copyright (C) 2011 by Joey Sabey (GameFreak7744@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
class User
{
	//Version string...
	const VERSION = 'trunk';
	
	//Configuration parameters
	const DB_PATH = '/f5/gamefreakslab/public/projects/UserClass/User_example.db';
	const SALT_LENGTH = 16;
	const SESSION_KEY_LENGTH = 32;
	const CONFIRM_CODE_LENGTH = 16;
	const HASH_ALGORITHM = 'sha512';
	const HASH_ITERATIONS = 256;
	const USERNAME_REGEX = '/^\w{4,32}$/';
	const PASSWORD_REGEX = '/^.{6,128}$/';
	const EMAIL_REGEX = '/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i';
	const COOKIE_SESSION_LENGTH = 604800; //In seconds = 7 days
	const COOKIE_PATH = '';		//Passed to the setcookie() path parameter
	const COOKIE_DOMAIN = '';	//Passed to the setcookie() domain parameter
	const LOGIN_FREQUENCY_LIMIT = 1.0;
	const LOGIN_FAILURE_LIMIT = 5;
	const LOGIN_FAILURE_PERIOD = 300; //In seconds = 5 minutes
	COnst LOGIN_FAILURE_COOLDOWN = 300; //In seconds = 5 minutes 
	
	//Login templates
	const LOGIN_FORM_TEMPLATE	= '<form id="login_form" action="[form_action]" method="POST" accept-charset="UTF-8" name="login_form">[error]<fieldset id="login_form_group"><legend id="form_legend">User login form</legend><label id="username_label" for="username_field">Username:<input id="username_field" type="text" name="username" value="[username]" /></label><label id="password_label" for="password_field">Password:<input id="password_field" type="password" name="password" /></label><label id="login_button_label" for="login_button"><input id="login_button" type="submit" value="Login" /></label></fieldset></form>';
	const LOGIN_SUCCESS_TEMPLATE = '<p>Successfully logged in as [username]!</p>';
	
	//Register templates
	const REGISTER_FORM_TEMPLATE	= '<form id="register_form" action="[form_action]" method="POST" accept-charset="UTF-8" name="register_form">[error]<fieldset id="register_form_group"><legend id="form_legend">User registration form</legend><label id="username_label" for="username_field">Username:<input id="username_field" type="text" name="username" value="[username]" /></label><label id="email_label" for="email_field">Email:<input id="email_field" type="email" name="email" value="[email]" /></label><label id="password_label" for="password_field">Password:<input id="password_field" type="password" name="password" /></label><label id="confirm_password_label" for="confirm_password_field">Confirm password:<input id="confirm_password_field" type="password" name="passwordConfirm" /></label><label id="register_button_label" for="register_button"><input id="register_button" type="submit" value="Register" /></label></fieldset></form>';
	const REGISTER_SUCCESS_TEMPLATE = '<p>Your account has been successfully registered, and an email has been sent to you containing a link to confirm your email address and activate your account.</p>';
	
	//Login errors
	const LOGIN_NO_USERNAME_ERROR = 'You must enter your username to log in';
	const LOGIN_NO_PASSWORD_ERROR = 'You must enter your password to log in';
	const LOGIN_NO_INPUT_ERROR = 'You must enter your username and password to log in';
	const LOGIN_INVALID_USERNAME_ERROR = 'The username entered was not a valid username';
	const LOGIN_INVALID_PASSWORD_ERROR = 'The password entered was not a valid password';
	const LOGIN_NO_SUCH_USERNAME_ERROR = 'The username entered does not exist';
	const LOGIN_INCORRECT_PASSWORD_ERROR = 'Incorrect password entered';
	const LOGIN_COOLDOWN_ERROR = 'Too many login attempts in the last few minutes, which could mean your account is under attack; login is temporarily disabled, please try again in 5-10 minutes.';
	const LOGIN_FREQUENCY_ERROR = 'Multiple login attempts detected in the last few moments, login cancelled because your account could be under attack, please try again.';
	
	//Register errors
	const REGISTER_NO_USERNAME_ERROR = 'You must choose a username to register';
	const REGISTER_NO_PASSWORD_ERROR = 'You must choose a password to register';
	const REGISTER_NO_CONFIRM_PASSWORD_ERROR = 'You must confirm your password to register';
	const REGISTER_NO_EMAIL_ERROR = 'You must enter your email address to register';
	const REGISTER_INVALID_USERNAME_ERROR = 'The username you have chosen is not valid';
	const REGISTER_INVALID_PASSWORD_ERROR = 'The password you have chosen is not valid';
	const REGISTER_INVALID_EMAIL_ERROR = 'You must enter a valid email address to register';
	const REGISTER_PASSWORD_MISMATCH_ERROR = 'The passwords you entered do not match';
	const REGISTER_UNAVAILABLE_USERNAME_ERROR = 'The username you have chosen is already registered';
	const REGISTER_UNAVAILABLE_EMAIL_ERROR = 'The email address you have entered is already in use at this site, you may have already registered an account';
	
	//Confirm templates
	//Email:
	const CONFIRM_SUBJECT = 'Confirm your account at XYZ';
	const CONFIRM_BODY_TEMPLATE = 'http://lab.s4t4n.net/projects/UserClass/demo/confirm.php?id=[id]&code=[code]';
	const CONFIRM_FROM = 'accounts@lab.s4t4n.net';
	//General:
	const CONFIRM_SUCCESS_TEMPLATE = 'Email confirmed; you may now log in.';
	const CONFIRM_INCORRECT_CODE_TEMPLATE = 'Confirmation code incorrect, carefully recopy the link into your browser and try again.';
	const CONFIRM_NO_SUCH_ID_TEMPLATE = 'Could not find that account to confirm; it may already have been confirmed.';
	
	//Set email confirm templates
	//Email:
	const SET_EMAIL_CONFIRM_SUBJECT = 'Confirm your new email address at XYZ';
	const SET_EMAIL_CONFIRM_BODY_TEMPLATE = 'http://lab.s4t4n.net/projects/UserClass/demo/confirm_email.php?id=[id]&code=[code]';
	const SET_EMAIL_CONFIRM_FROM = 'accounts@lab.s4t4n.net';
	//General:
	const SET_EMAIL_CONFIRM_SUCCESS_TEMPLATE = 'Email change confirmed.';
	const SET_EMAIL_CONFIRM_INCORRECT_CODE_TEMPLATE = 'Confirmation code incorrect, carefully recopy the link into your browser and try again';
	const SET_EMAIL_CONFIRM_NO_SUCH_ID_TEMPLATE = 'Could not find that email change request to confirm; it may already have been confirmed';
	
	//Flags
	const GET_BY_ID = 0;
	const GET_BY_USERNAME = 1;
	const SET_EMAIL_CONFIRM = 0;
	const SET_EMAIL_DIRECT = 1;
	
	//Class variables
	protected $id = NULL;
	protected $username = NULL;
	protected $password = NULL;
	protected $salt = NULL;
	protected $email = NULL;
	protected $date = NULL;
	protected $sessionKey = NULL;
	protected $sessionIP = NULL;
	protected $failureCount = NULL;
	protected $failureTime = NULL;
	
	//Class constructor; loads User data from the database by id or username
	//Maybe make consturctor private/protected, limiting construction to get()?
	public function __construct($uid, $getType = User::GET_BY_ID)
	{
		$db = new PDO('sqlite:'.User::DB_PATH);
		if($getType == User::GET_BY_ID)
		{
			//Need to revise this exception..?
			if(!is_int($uid))
				throw new InvalidArgumentException('User class constructor expected integer, value given was: '.$uid);
			$query = $db->prepare('SELECT * FROM users WHERE id = :id');
			$query->bindParam(':id', $uid, PDO::PARAM_INT);
		}
		else if($getType == User::GET_BY_USERNAME)
		{
			if(!User::validateUsername($uid))
				throw new UserInvalidUsernameException($uid);
			$query = $db->prepare('SELECT * FROM users WHERE username = :username');
			$query->bindParam(':username', $uid, PDO::PARAM_STR);
		}
		//else THROW ERROR
		$query->execute();
		$query->bindColumn('id', $this->id, PDO::PARAM_INT);
		$query->bindColumn('username', $this->username, PDO::PARAM_STR);
		$query->bindColumn('password', $this->password, PDO::PARAM_STR);
		$query->bindColumn('salt', $this->salt, PDO::PARAM_LOB);
		$query->bindColumn('email', $this->email, PDO::PARAM_STR);
		$query->bindColumn('date', $this->date, PDO::PARAM_INT);
		$query->bindColumn('sessionKey', $this->sessionKey, PDO::PARAM_STR);
		$query->bindColumn('sessionIP', $this->sessionIP, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		//May need to revise type of exception thrown here...
		if($this->id == NULL)
			throw new OutOfBoundsException('No such user found in database: '.$id);
	}
	
	public function getID(){
		return $this->id;
	}
	public function getUsername(){
		return $this->username;
	}
	public function getPassword(){
		return $this->password;
	}
	public function getSalt(){
		return $this->salt;
	}
	public function getEmail(){
		return $this->email;
	}
	public function getDate(){
		return $this->date;
	}
	public function getSessionKey(){
		return $this->sessionKey;
	}
	public function getSessionIP(){
		return $this->sessionIP;
	}
	public function getFailureCount(){
		return $this->failureCount;
	}
	public function getFailureTime(){
		return $this->failureTime;
	}
	
	//Validates $username, then updates the database & member
	public function setUsername($username)
	{
		if(!User::validateUsername($username))
			throw new UserInvalidUsernameException($username);
		if(!User::availableUsername($username))
			throw new UserUnavailableUsernameException($username);
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET username=:username WHERE id=:id');
		$query->bindParam(':username', $username, PDO::PARAM_STR);
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->username = $username;
	}
	
	//Validates $password, then updates database & member
	public function setPassword($password)
	{
		if(!User::validatePassword($password))
			throw new UserInvalidPasswordException($password);
		$salt = User::generateSalt();
		$password = processPassword($password, $salt);
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET password=:password, salt=:salt WHERE id=:id');
		$query->bindParam(':password', $password, PDO::PARAM_STR);
		$query->bindParam(':salt', $salt, PDO::PARAM_LOB);
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->password = $password;
		$this->salt = $salt;
	}
	
	//This method needs revision to confirm new email
	public function setEmail($email, $mode = User::SET_EMAIL_CONFIRM)
	{
		if(!User::validateEmail($email))
			throw new UserInvalidEmailException($email);
		if(!User::availableEmail($email))
			throw new UserUnavailableEmailException($email);
		$db = new PDO('sqlite:'.User::DB_PATH);
		if($mode == User::SET_EMAIL_CONFIRM)
		{
			$confirmCode = User::generateConfirmCode();
			$query = $db->prepare('INSERT INTO usersChangeEmail(userID, email, confirmCode) VALUES(:userID, :email, :confirmCode)');
			$query->bindParam(':userID', $this->id, PDO::PARAM_INT);
			$query->bindParam(':email', $email, PDO::PARAM_STR);
			$query->bindParam(':confirmCode', hash(User::HASH_ALGORITHM, $confirmCode), PDO::PARAM_STR);
			$query->execute();
			//SEND EMAIL HERE!
			$body = User::SET_EMAIL_CONFIRM_BODY_TEMPLATE;
			$body = str_replace('[id]', $db->lastInsertId(), $body);
			$body = str_replace('[code]', $confirmCode, $body);
			mail($email, User::SET_EMAIL_CONFIRM_SUBJECT, $body, 'From: '.User::SET_EMAIL_CONFIRM_FROM);
		}
		else if($mode == User::SET_EMAIL_DIRECT)
		{
			$query = $db->prepare('UPDATE users SET email=:email WHERE id=:id');
			$query->bindParam(':email', $email, PDO::PARAM_STR);
			$query->bindParam(':id', $this->id, PDO::PARAM_INT);
			$query->execute();
			$this->email = $email;
		}
		else
			throw new InvalidArgumentException('Invalid mode for setEmail method, mode is either SET_EMAIL_CONFIRM or SET_EMAIL_DIRECT');
	}
	
	//Checks $count is a positive integer, then updates the database & member
	public function setFailureCount($count)
	{
		if(!is_int($count))
			throw new InvalidArgumentException('setFailureCount() expected integer, value given was: '.$count);
		if($count < 0)
			throw new InvalidArgumentException('setFailureCount() expected a positive integer, or 0, value given was: '.$count);
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET failureCount=:count WHERE id=:id');
		$query->bindParam(':count', $count, PDO::PARAM_INT);
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->failureCount = $count;
	}
	
	//Updates the last failure time to current time in the db and object
	public function setFailureTime($time = -1)
	{
		if($time == -1)
			$time = gettimeofday(true);
		else
		{
			if(!is_numeric($time))
				throw new InvalidArgumentException('setFailureTime() expected a number, value given was: '.$time);
			if($time < 0)
				throw new InvalidArgumentException('setFailureTime() expected a positive value, value given was: '.$time);
			if($time > gettimeofday(true))
				throw new RangeException('setFailureTime() can only be called with timestamps up to the current time, or -1 for the current time');
		}
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET failureTime=:time WHERE id=:id');
		$query->bindValue(':time', strval($time));
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->failureTime = $time;
	}
	
	//Checks if the user is currently in a cooldown due to a potential brute force attack, resets failureCount if
	//if it -was- in cooldown, but the cooldown has expired
	public function loginLimitExceeded()
	{
		if($this->failureCount >= User::LOGIN_FAILURE_LIMIT)
			if(gettimeofday(true) - $this->failureTime < User::LOGIN_FAILURE_COOLDOWN)
				return true; //Also reset last attempt?
		$this->setFailureCount(0);
		return false;
	}
	
	//Checks if the last login was a permittable number of seconds ago to allow a login attempt, returns true if so
	public function checkLoginFrequency()
	{
		if(is_null($this->failureTime))
			return true;
		if($this->failureTime == 0)
			return true;
		if(gettimeofday(true) - $this->failureTime < User::LOGIN_FREQUENCY_LIMIT)
		{
			$this->loginFailure();
			return false;
		}
		return true;
	}
	
	//Checks $password against the stored password; returns true if it matches, false otherwise
	public function checkPassword($password)
	{
		if(User::processPassword($password, $this->salt) == $this->password)
			return true;
		return false;
	}
	
	//Logs a failed login attempt, setting failureCount & failureTime appropriately
	public function loginFailure()
	{
		if(gettimeofday(true) - $this->failureTime > User::LOGIN_FAILURE_PERIOD)
			$this->setFailureCount(1);
		else
			$this->setFailureCount($this->failureCount + 1);
		$this->setFailureTime();
	}
	
	//Generates a new session key; sends out login cookies; updates the database & members
	public function startSession()
	{
		//Ready session data...
		$sessionKey = User::generateSessionKey();
		$hashedKey = hash(User::HASH_ALGORITHM, $sessionKey);
		$sessionIP = $_SERVER['REMOTE_ADDR'];
		//Send session cookies...
		User::sendCookies($this->username, $sessionKey);
		//Update database...
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET sessionKey=:sessionKey, sessionIP=:sessionIP WHERE id=:id');
		$query->bindParam(':sessionKey', $hashedKey, PDO::PARAM_STR);
		$query->bindParam(':sessionIP', $sessionIP, PDO::PARAM_STR);
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		//Update members...
		$this->sessionKey = $hashedKey;
		$this->sessionIP = $sessionIP;
	}
	
	//Checks if User has valid login session for the current script; checks if logged in
	public function checkSession($sessionKey)
	{
		if($_SERVER['REMOTE_ADDR'] != $this->sessionIP)
			return false;
		if(hash(User::HASH_ALGORITHM, $sessionKey) != $this->sessionKey)
			return false;
		return true;
	}
	
	public function endSession()
	{
		//Remove cookies...
		User::removeCookies();
		//Remove database data...
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('UPDATE users SET sessionKey=NULL, sessionIP=NULL WHERE id=:id');
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		//Remove member data...
		$this->sessionKey = NULL;
		$this->sessionIP = NULL;
	}

	public function remove()
	{
		//Prep database...
		$db = new PDO('sqlite:'.User::DB_PATH);
		//Remove the record in the users table...
		$query = $db->prepare('DELETE FROM users WHERE id=:id');
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		//Remove any record in the usersChangeEmail table... 
		$query = $db->prepare('DELETE FROM usersChangeEmail WHERE userID=:id');
		$query->bindParam(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
	}
	
	//Returns a new User object representing the user currently logged in, determined by cookies
	public static function getCurrent()
	{
		if(!array_key_exists('username', $_COOKIE))
			return NULL;
		$current = new User($_COOKIE['username'], User::GET_BY_USERNAME);
		if($current->checkSession($_COOKIE['sessionKey']))
			return $current;
		return NULL;
	}
		
	//Adds a new user straight to the database; does not require email validation!
	public static function add($username, $password, $email)
	{
		//Error checking/validation...
		if(!User::validateUsername($username))
			throw new UserInvalidUsernameException($username);
		if(!User::validatePassword($password))
			throw new UserInvalidPasswordException($password);
		if(!User::validateEmail($email))
			throw new UserInvalidEmailException($email);
		if(!User::availableUsername($username))
			throw new UserUnavailableUsernameException($username); 
		if(!User::availableEmail($email))
			throw new UserUnavailableEmailException($email);   
		//Main code follows...
		$salt = User::generateSalt();
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('INSERT INTO users(username, password, salt, email, date) VALUES(:username, :password, :salt, :email, :date)');
		$query->bindParam(':username', $username, PDO::PARAM_STR);
		$query->bindParam(':password', User::processPassword($password, $salt), PDO::PARAM_STR);
		$query->bindParam(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
		$query->bindParam(':email', $email, PDO::PARAM_STR);
		$query->bindParam(':date', time(), PDO::PARAM_STR);
		$query->execute();	
	}
	
	//Adds a new user to the usersPending database; sends an email out for confirmation
	public static function addPending($username, $password, $email)
	{
		//Error checking/validation...
		if(!User::validateUsername($username))
			throw new UserInvalidUsernameException($username);
		if(!User::validatePassword($password))
			throw new UserInvalidPasswordException($password);
		if(!User::validateEmail($email))
			throw new UserInvalidEmailException($email);
		if(!User::availableUsername($username))
			throw new UserUnavailableUsernameException($username);                                                     
		if(!User::availableEmail($email))
			throw new UserUnavailableEmailException($email);   
		//Main code follows...
		$salt = User::generateSalt();
		$confirmCode = User::generateConfirmCode();
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('INSERT INTO usersPending(username, password, salt, email, date, confirmCode) VALUES(:username, :password, :salt, :email, :date, :confirmCode)');
		$query->bindParam(':username', $username, PDO::PARAM_STR);
		$query->bindParam(':password', User::processPassword($password, $salt), PDO::PARAM_STR);
		$query->bindParam(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
		$query->bindParam(':email', $email, PDO::PARAM_STR);
		$query->bindParam(':date', time(), PDO::PARAM_STR);
		$query->bindParam(':confirmCode', hash(User::HASH_ALGORITHM, $confirmCode), PDO::PARAM_STR);
		$query->execute();
		//Send confirm email...
		$body = User::CONFIRM_BODY_TEMPLATE;
		$body = str_replace('[id]', $db->lastInsertId(), $body);
		$body = str_replace('[code]', $confirmCode, $body);
		mail($email, User::CONFIRM_SUBJECT, $body, 'From: '.User::CONFIRM_FROM);
	}
	
	//Should this be a single success+act-or-error method similar to login()?
	public static function confirm()
	{
		//validate input here..?
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('SELECT * FROM usersPending WHERE id = :id');
		$query->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
		$query->execute();
		$query->bindColumn('username', $username, PDO::PARAM_STR);
		$query->bindColumn('password', $password, PDO::PARAM_STR);
		$query->bindColumn('salt', $salt, PDO::PARAM_LOB);
		$query->bindColumn('email', $email, PDO::PARAM_STR);
		$query->bindColumn('date', $date, PDO::PARAM_INT);
		$query->bindColumn('confirmCode', $confirmCode, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		if($username == NULL)
			return User::CONFIRM_NO_SUCH_ID_TEMPLATE;
		if(hash(User::HASH_ALGORITHM, $_GET['code']) == $confirmCode)
		{
			//Copy over data to users table...
			$db = new PDO('sqlite:'.User::DB_PATH);
			$query = $db->prepare('INSERT INTO users(username, password, salt, email, date) VALUES(:username, :password, :salt, :email, :date)');
			$query->bindParam(':username', $username, PDO::PARAM_STR);
			$query->bindParam(':password', $password, PDO::PARAM_STR);
			$query->bindParam(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
			$query->bindParam(':email', $email, PDO::PARAM_STR);
			$query->bindParam(':date', $date, PDO::PARAM_STR);
			$query->execute();
			//Remove entry from usersPending...
			$query = $db->prepare('DELETE FROM usersPending WHERE id = :id');
			$query->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
			$query->execute();
			return User::CONFIRM_SUCCESS_TEMPLATE;
		}
		return User::CONFIRM_INCORRECT_CODE_TEMPLATE;
	}
	
	//This method should be called on a page setup to confirm email changes; returns success or error message
	public static function confirmSetEmail()
	{
		//validate input here..?
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('SELECT * FROM usersChangeEmail WHERE id = :id');
		$query->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
		$query->execute();
		$query->bindColumn('userID', $userID, PDO::PARAM_INT);
		$query->bindColumn('email', $email, PDO::PARAM_STR);
		$query->bindColumn('confirmCode', $confirmCode, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		if($email == NULL)
			return User::SET_EMAIL_CONFIRM_NO_SUCH_ID_TEMPLATE;
		if(hash(User::HASH_ALGORITHM, $_GET['code']) == $confirmCode)
		{
			//Update users email in database...
			$query = $db->prepare('UPDATE users SET email=:email WHERE id=:id');
			$query->bindParam(':email', $email, PDO::PARAM_STR);
			$query->bindParam(':id', $userID, PDO::PARAM_INT);
			$query->execute();
			//Remove entry from usersChangeEmail...
			$query = $db->prepare('DELETE FROM usersChangeEmail WHERE id = :id');
			$query->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
			$query->execute();
			return User::SET_EMAIL_CONFIRM_SUCCESS_TEMPLATE;
		}
		return User::SET_EMAIL_CONFIRM_INCORRECT_CODE_TEMPLATE;
	}
	
	//This function should be called at the -top- of a login page, before any output; it returns
	// either a success message (and logins in the user), or a form (with appropriate errors)
	public static function login()
	{
		$username = NULL;
		$password = NULL;
		$error = NULL;
		
		if(isset($_POST['username']))
		{
			//Check if form was filled out completely...
			if($_POST['username'] == '' && $_POST['password'] == '')
				return User::processLoginForm(User::LOGIN_NO_INPUT_ERROR);
			if($_POST['username'] == '')
				return User::processLoginForm(User::LOGIN_NO_USERNAME_ERROR);
			if($_POST['password'] == '')
				return User::processLoginForm(User::LOGIN_NO_PASSWORD_ERROR, $_POST['username']);
			//Check if entered details are valid...
			if(!User::validateUsername($_POST['username']))
				return User::processLoginForm(User::LOGIN_INVALID_USERNAME_ERROR);
			if(!User::validatePassword($_POST['password']))
				return User::processLoginForm(User::LOGIN_INVALID_PASSWORD_ERROR, $_POST['username']);
			//Try finding in the user...
			try
				$user = new User($_POST['username'], User::GET_BY_USERNAME);
			catch(OutOfBoundsException $e)
				return User::processLoginForm(User::LOGIN_NO_SUCH_USER_ERROR);
//			if($user == NULL)
//				return User::processLoginForm(User::LOGIN_NO_SUCH_USER_ERROR);
			//Check if user is in cooldown
			if($user->loginLimitExceeded())
				return User::processLoginForm(User::LOGIN_COOLDOWN_ERROR, $_POST['username']);
			//Check for unnaturally frequent login attempts
			if(!$user->checkLoginFrequency())
				return User::processLoginForm(User::LOGIN_FREQUENCY_ERROR, $_POST['username']);
			//Check if the passwords match...
			if(!$user->checkPassword($_POST['password']))
			{
				$user->loginFailure();
				return User::processLoginForm(User::LOGIN_INCORRECT_PASSWORD_ERROR, $_POST['username']);
			}
			//Success...
			$user->startSession();
			$user->setFailureCount(0);
			$user->setFailureTime(0);
			return str_replace('[username]', $user->getUsername(), User::LOGIN_SUCCESS_TEMPLATE);
		}
		return User::processLoginForm();
	}
	
	//This function inserts the dynamic elements into the login form template
	protected static function processLoginForm($error = '', $username = '')
	{
		$form = User::LOGIN_FORM_TEMPLATE;
		$form = str_replace('[form_action]', $_SERVER['PHP_SELF'], $form);
		$form = str_replace('[error]', $error, $form);
		$form = str_replace('[username]', $username, $form);
		return $form;
	}
	
	//This method should be called at the appropriate point on the registration page to
	// print the form/success message; returns a string containing the form (with errors
	// as necessary) or a success message
	public static function register()
	{
		//If form hasn't been posted, return form...
		if(!isset($_POST['username']))
			return User::processRegisterForm();
		//Check if form was filled out completely...
		if($_POST['username'] == '')
			return User::processRegisterForm(User::REGISTER_NO_USERNAME_ERROR, NULL, $_POST['email']);
		if($_POST['email'] == '')
			return User::processRegisterForm(User::REGISTER_NO_EMAIL_ERROR, $_POST['username']);
		if($_POST['password'] == '')
			return User::processRegisterForm(User::REGISTER_NO_PASSWORD_ERROR, $_POST['username'], $_POST['email']);
		if($_POST['passwordConfirm'] == '')
			return User::processRegisterForm(User::REGISTER_NO_CONFIRM_PASSWORD_ERROR, $_POST['username'], $_POST['email']);
		//Check if entered details are valid...
		if(!User::validateUsername($_POST['username']))
			return User::processRegisterForm(User::REGISTER_INVALID_USERNAME_ERROR, NULL, $_POST['email']);
		if(!User::validateEmail($_POST['email']))
			return User::processRegisterForm(User::REGISTER_INVALID_EMAIL_ERROR, $_POST['username']);
		if(!User::validatePassword($_POST['password']))
			return User::processRegisterForm(User::REGISTER_INVALID_PASSWORD_ERROR, $_POST['username'], $_POST['email']);
		//Check if username & email are available...
		if(!User::availableUsername($_POST['username']))
			return User::processRegisterForm(User::REGISTER_UNAVAILABLE_USERNAME_ERROR, NULL, $_POST['email']);
		if(!User::availableEmail($_POST['email']))
			return User::processRegisterForm(User::REGISTER_UNAVAILABLE_EMAIL_ERROR, $_POST['username']);
		//Ensure passwords match...
		if($_POST['password'] != $_POST['passwordConfirm'])
			return User::processRegisterForm(User::REGISTER_PASSWORD_MISMATCH_ERROR, $_POST['username'], $_POST['email']);
		//Add user to the usersPending table..
		User::addPending($_POST['username'], $_POST['password'], $_POST['email']);
		return User::REGISTER_SUCCESS_TEMPLATE;
	}
	
	//This function inserts the dynamic elements into the register form template
	protected static function processRegisterForm($error = '', $username = '', $email = '')
	{
		$form = User::REGISTER_FORM_TEMPLATE;
		$form = str_replace('[form_action]', $_SERVER['PHP_SELF'], $form);
		$form = str_replace('[error]', $error, $form);
		$form = str_replace('[username]', $username, $form);
		$form = str_replace('[email]', $email, $form);
		return $form;
	}
	
	//Checks that $username follows the pre-defined conventions
	protected static function validateUsername($username)
	{
		if(preg_match(User::USERNAME_REGEX, $username))
			return true;
		return false;
	}
	
	//Checkt that $password follws the pre-defined conventions
	protected static function validatePassword($password)
	{
		if(preg_match(User::PASSWORD_REGEX, $password))
			return true;
		return false;
	}
	
	//Ensures $emails at least -looks- like a real email address
	protected static function validateEmail($email)
	{
		if(preg_match(User::EMAIL_REGEX, $email))
			return true;
		return false;
	}
	
	//Checks if $username already exists in database; returns true if it doesn't, otherwise false
	protected static function availableUsername($username)
	{
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('SELECT COUNT (*) FROM users WHERE username = :username');
		$query->bindParam(':username', $username, PDO::PARAM_STR);
		$query->execute();
		if($query->fetchColumn() == 0)
		{
			$query = $db->prepare('SELECT COUNT (*) FROM usersPending WHERE username = :username');
			$query->bindParam(':username', $username, PDO::PARAM_STR);
			$query->execute();
			if($query->fetchColumn() == 0)
				return true;
		}
		return false;
	}
	
	//Checks if $email already exists in database; returns true if it doesn't, otherwise false
	protected static function availableEmail($email)
	{
		$db = new PDO('sqlite:'.User::DB_PATH);
		$query = $db->prepare('SELECT COUNT (*) FROM users WHERE email = :email');
		$query->bindParam(':email', $email, PDO::PARAM_STR);
		$query->execute();
		if($query->fetchColumn() == 0)
		{
			$query = $db->prepare('SELECT COUNT (*) FROM usersPending WHERE email = :email');
			$query->bindParam(':email', $email, PDO::PARAM_STR);
			$query->execute();
			if($query->fetchColumn() == 0)
				return true;
		}
		return false;
	}
	
	//This method salts the password, and then hashes it multiple times
	protected static function processPassword($password, $salt)
	{
		$salted = $password.$salt;
		for($x = 0; $x < User::HASH_ITERATIONS; $x++)
			$salted = hash(User::HASH_ALGORITHM, $salted);
		return $salted;
	}
	
	//Generates a random salt with a pre-determined length
	protected static function generateSalt()
	{
		return mcrypt_create_iv(User::SALT_LENGTH, MCRYPT_DEV_URANDOM);
	}
	
	//Generates a random session key with a pre-determined length
	protected static function generateSessionKey()
	{
		$key = mcrypt_create_iv(User::SESSION_KEY_LENGTH, MCRYPT_DEV_URANDOM);
		return hash(User::HASH_ALGORITHM, $key);
	}
	
	//Generates a random confirmation code with a pre-determined length; result is hashed for email/url
	protected static function generateConfirmCode()
	{
		$code = mcrypt_create_iv(User::CONFIRM_CODE_LENGTH, MCRYPT_DEV_URANDOM);
		return sha1($code);
	}
	
	//Sends out login cookies, with a few pre-defined parameters
	protected static function sendCookies($username, $sessionKey)
	{
		if(User::COOKIE_SESSION_LENGTH == 0)
			$expire = 0;
		else
			$expire = time() + User::COOKIE_SESSION_LENGTH;
		setcookie('username',
			  $username,
			  $expire,
			  User::COOKIE_PATH,
			  User::COOKIE_DOMAIN,
			  false,
			  true);
		setcookie('sessionKey',
			  $sessionKey,
			  $expire,
			  User::COOKIE_PATH,
			  User::COOKIE_DOMAIN,
			  false,
			  true);
		$_COOKIE['username'] = $username;
		$_COOKIE['sessionKey'] = $sessionKey;
	}
	
	//Blanks login cookies, and removes them from the $_COOKIE array
	protected static function removeCookies()
	{
		setcookie('username', NULL, -1);
		setcookie('sessionKey', NULL, -1);
		$_COOKIE['username'] = NULL;
		$_COOKIE['sessionKey'] = NULL;
	}
	
	//This method must be called to setup the database before any other code is called
	public static function setupDB()
	{
		$db = new PDO('sqlite:'.User::DB_PATH);
		//Create 'users' table...
		$query = $db->prepare(
		'CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,
						  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
						  password TEXT NOT NULL,
						  salt BLOB NOT NULL,
						  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
						  date INTEGER NOT NULL,
						  sessionKey TEXT,
						  sessionIP TEXT,
                                                  failureCount INTEGER,
                                                  failureTime REAL)');
		$query->execute();
		//Create 'usersPending' table...
		$query = $db->prepare(
		'CREATE TABLE IF NOT EXISTS usersPending(id INTEGER PRIMARY KEY,
							 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
							 password TEXT NOT NULL,
							 salt BLOB NOT NULL,
							 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
							 date INTEGER NOT NULL,
							 confirmCode TEXT NOT NULL)');
		$query->execute();
		//Create 'usersChangeEmail' table...
		$query = $db->prepare(
		'CREATE TABLE IF NOT EXISTS usersChangeEmail(id INTEGER PRIMARY KEY,
							     userID INTEGER UNIQUE NOT NULL,
							     email TEXT NOT NULL UNIQUE COLLATE NOCASE,
							     confirmCode TEXT NOT NULL)');
		//FOREIGN KEY UNITQUE NOT NULL (userID) REFERENCES users(id), //Requires sqlite version ~3.6? 3.3.7 available...
		$query->execute();
	}
}

//CLASS SPECIFIC EXCEPTIONS FOLLOW
class UserInvalidUsernameException extends InvalidArgumentException{
	public function __construct($value){
		parent::__construct('Invalid username: '.$value);
	}
}
class UserInvalidPasswordException extends InvalidArgumentException{
	public function __construct($value){
		parent::__construct('Invalid password: '.$value);
	}
}
class UserInvalidEmailException extends InvalidArgumentException{
	public function __construct($value){
		parent::__construct('Invalid email: '.$value);
	}
}
class UserUnavailableUsernameException extends InvalidArgumentException{
	public function __construct($value){
		parent::__construct('Username \''.$value.'\' already exists in database.');
	}
}
class UserUnavailableEmailException extends InvalidArgumentException{
	public function __construct($value){
		parent::__construct('Email \''.$value.'\' already exists in database.');
	}
}

?>
