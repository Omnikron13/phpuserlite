<?php
/*
Copyright (C) 2011-2017 by Joey Sabey (GameFreak7744@gmail.com)

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
	const DEFAULT_CONFIG_FILE = 'phpuserlite.cfg';
	
	protected static $configData = [
		//Configuration parametres
		'db_path'		=>	'phpuserlite.db',
		'salt_length'		=>	16,
		'session_key_length'	=>	32,
		'confirm_code_length'	=>	16,
		'request_token_length'	=>	16,
		'hash_algorithm'	=>	'sha512',
		'hash_iterations'	=>	32000,
		'username_regex'	=>	'/^\w{4,32}$/',
		'password_regex'	=>	'/^.{6,128}$/',
		'email_regex'		=>	'/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i',
		'cookie_session_length'	=>	604800,
		'cookie_path'		=>	'',
		'cookie_domain'		=>	'',
		'login_frequency_limit'	=>	1.0,
		'login_failure_limit'	=>	5,
		'login_failure_period'	=>	300,
		'login_failure_cooldown'=>	300,
        'max_sessions' => 1,
		
		//Login templates
		'login_form_template'
			=>	'<form id="login_form" action="" method="POST" accept-charset="UTF-8" name="login_form">[error]<fieldset id="login_form_group"><legend id="form_legend">User login form</legend><label id="username_label" for="username_field">Username:<input id="username_field" type="text" name="username" value="[username]" /></label><label id="password_label" for="password_field">Password:<input id="password_field" type="password" name="password" /></label><label id="login_button_label" for="login_button"><input id="login_button" type="submit" value="Login" /></label></fieldset></form>',
		'login_success_template'
			=>	'<p>Successfully logged in as [username]!</p>',
		
		//Register templates
		'register_form_template'
			=>	'<form id="register_form" action="" method="POST" accept-charset="UTF-8" name="register_form">[error]<fieldset id="register_form_group"><legend id="form_legend">User registration form</legend><label id="username_label" for="username_field">Username:<input id="username_field" type="text" name="username" value="[username]" /></label><label id="email_label" for="email_field">Email:<input id="email_field" type="email" name="email" value="[email]" /></label><label id="password_label" for="password_field">Password:<input id="password_field" type="password" name="password" /></label><label id="confirm_password_label" for="confirm_password_field">Confirm password:<input id="confirm_password_field" type="password" name="passwordConfirm" /></label><label id="register_button_label" for="register_button"><input id="register_button" type="submit" value="Register" /></label></fieldset></form>',
		'register_success_template'
			=>	'<p>Your account has been successfully registered, and an email has been sent to you containing a link to confirm your email address and activate your account.</p>',
		
		//Login error
		'login_no_username_error'	=>	'You must enter your username to log in',
		'login_no_password_error'	=>	'You must enter your password to log in',
		'login_no_input_error'		=>	'You must enter your username and password to log in',
		'login_invalid_username_error'	=>	'The username entered was not a valid username',
		'login_invalid_password_error'	=>	'The password entered was not a valid password',
		'login_no_such_username_error'	=>	'The username entered does not exist',
		'login_incorrect_password_error'=>	'Incorrect password entered',
		'login_cooldown_error'		=>	'Too many login attempts in the last few minutes, which could mean your account is under attack; login is temporarily disabled, please try again in 5-10 minutes.',
		'login_frequency_error'		=>	'Multiple login attempts detected in the last few moments, login cancelled because your account could be under attack, please try again.',
		
		//Register errors
		'register_no_username_error'		=>	'You must choose a username to register',
		'register_no_password_error'		=>	'You must choose a password to register',
		'register_no_confirm_password_error'	=>	'You must confirm your password to register',
		'register_no_email_error'		=>	'You must enter your email address to register',
		'register_invalid_username_error'	=>	'The username you have chosen is not valid',
		'register_invalid_password_error'	=>	'The password you have chosen is not valid',
		'register_invalid_email_error'		=>	'You must enter a valid email address to register',
		'register_password_mismatch_error'	=>	'The passwords you entered do not match',
		'register_unavailable_username_error'	=>	'The username you have chosen is already registered',
		'register_unavailable_email_error'	=>	'The email address you have entered is already in use at this site, you may have already registered an account',
		
		//Confirm templates
		//Email:
		'confirm_subject'
			=>	'Confirm your account at XYZ',
		'confirm_body_template'
			=>	'http://example.com/confirm.php?id=[id]&code=[code]',
		'confirm_from'
			=>	'accounts@example.com',
		//General:
		'confirm_success_template'
			=>	'Email confirmed; you may now log in.',
		'confirm_incorrect_code_template'
			=>	'Confirmation code incorrect, carefully recopy the link into your browser and try again.',
		'confirm_no_such_id_template'
			=>	'Could not find that account to confirm; it may already have been confirmed.',
		
		//Set email confirm templates
		//Email:
		'set_email_confirm_subject'
			=>	'Confirm your new email address at XYZ',
		'set_email_confirm_body_template'
			=>	'http://example.com/confirm_email.php?id=[id]&code=[code]',
		'set_email_confirm_from'
			=>	'accounts@example.com',
		//General:
		'set_email_confirm_success_template'
			=>	'Email change confirmed.',
		'set_email_confirm_incorrect_code_template'
			=>	'Confirmation code incorrect, carefully recopy the link into your browser and try again',
		'set_email_confirm_no_such_id_template'
			=>	'Could not find that email change request to confirm; it may already have been confirmed',
		
		//Database schemas
		'db_users_table_schema'
			=>	'CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,
								  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
								  password TEXT NOT NULL,
								  salt BLOB NOT NULL,
								  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
								  date INTEGER NOT NULL,
								  failureCount INTEGER,
								  failureTime REAL,
                                  requestToken BLOB)',
		'db_userspending_table_schema'
			=>	'CREATE TABLE IF NOT EXISTS usersPending(id INTEGER PRIMARY KEY,
									 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
									 password TEXT NOT NULL,
									 salt BLOB NOT NULL,
									 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
									 date INTEGER NOT NULL,
									 confirmCode TEXT NOT NULL)',
		'db_userschangeemail_table_schema'
			=>	'CREATE TABLE IF NOT EXISTS usersChangeEmail(id INTEGER PRIMARY KEY,
									     userID INTEGER UNIQUE NOT NULL,
									     email TEXT NOT NULL UNIQUE COLLATE NOCASE,
									     confirmCode TEXT NOT NULL,
									     FOREIGN KEY (userID) REFERENCES users(id)
                                                ON DELETE CASCADE
                                                ON UPDATE CASCADE)',
        'db_userssessions_table_schema'
            => 'CREATE TABLE IF NOT EXISTS usersSessions(
                    id      INTEGER PRIMARY KEY,
                    userID  INTEGER NOT NULL,
                    key     TEXT    NOT NULL,
                    IP      TEXT    NOT NULL,
                    active  INTEGER NOT NULL,
                    FOREIGN KEY (userID) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                )',
    ];
	
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
	protected $sessions = [];
	protected $failureCount = NULL;
	protected $failureTime = NULL;
	protected static $db = NULL;
	
	//Class constructor; loads User data from the database by id or username
	//Maybe make consturctor private/protected, limiting construction to get()?
	public function __construct($uid, int $getType = User::GET_BY_ID)
	{
		$db = User::getDB();
		if($getType == User::GET_BY_ID)
		{
			//Need to revise this exception..?
			if(!is_int($uid))
				throw new UserIncorrectDatatypeException('__construct()', 1, 'integer', $uid);
			$query = $db->prepare('SELECT * FROM users WHERE id = :id');
			$query->bindValue(':id', $uid, PDO::PARAM_INT);
		}
		else if($getType == User::GET_BY_USERNAME)
		{
			if(!User::validateUsername($uid))
				throw new UserInvalidUsernameException($uid);
			$query = $db->prepare('SELECT * FROM users WHERE username = :username');
			$query->bindValue(':username', $uid, PDO::PARAM_STR);
		}
		else
			throw new UserInvalidModeException('__construct()', $getType, 'User::GET_BY_ID, User::GET_BY_USERNAME');
		$query->execute();
		$query->bindColumn('id', $this->id, PDO::PARAM_INT);
		$query->bindColumn('username', $this->username, PDO::PARAM_STR);
		$query->bindColumn('password', $this->password, PDO::PARAM_STR);
		$query->bindColumn('salt', $this->salt, PDO::PARAM_LOB);
		$query->bindColumn('email', $this->email, PDO::PARAM_STR);
		$query->bindColumn('date', $this->date, PDO::PARAM_INT);
		$query->bindColumn('failureCount', $this->failureCount, PDO::PARAM_INT);
		$query->bindColumn('failureTime', $this->failureTime, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		//May need to revise type of exception thrown here...
		if($this->id === NULL)
			throw new UserNoSuchUserException($uid, $getType);
		$query = $db->prepare('SELECT * FROM usersSessions WHERE userID = :userID');
		$query->bindValue(':userID', $this->id, PDO::PARAM_INT);
		$query->execute();
		foreach($query->fetchAll(PDO::FETCH_ASSOC) as $row)
            $this->sessions[$row['key']] = $row['IP'];
	}
	
	//Stringifies to just the username for the time being
    public function __toString() : string {
		return $this->username;
	}
	
    public function getID() : int {
		return $this->id;
	}
    public function getUsername() : string {
		return $this->username;
	}
    public function getPassword() : string {
		return $this->password;
	}
    public function getSalt() : string {
		return $this->salt;
	}
    public function getEmail() : string {
		return $this->email;
	}
    public function getDate() : int {
		return $this->date;
	}
    public function getSessions() : array {
		return $this->sessions;
	}
    public function getFailureCount() : ?int {
		return $this->failureCount;
	}
    public function getFailureTime() : ?float {
		return $this->failureTime;
	}
	
	//Validates $username, then updates the database & member
    public function setUsername(string $username) : void
	{
		if(!User::validateUsername($username))
			throw new UserInvalidUsernameException($username);
		if(!User::availableUsername($username))
			throw new UserUnavailableUsernameException($username);
		$db = User::getDB();
		$query = $db->prepare('UPDATE users SET username=:username WHERE id=:id');
		$query->bindValue(':username', $username, PDO::PARAM_STR);
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->username = $username;
		User::processEventHandlers('onUsernameChange', $this);
	}
	
	//Validates $password, then updates database & member
    public function setPassword(string $password) : void
	{
		if(!User::validatePassword($password))
			throw new UserInvalidPasswordException($password);
		$salt = User::generateSalt();
		$password = User::processPassword($password, $salt);
		$db = User::getDB();
		$query = $db->prepare('UPDATE users SET password=:password, salt=:salt WHERE id=:id');
		$query->bindValue(':password', $password, PDO::PARAM_STR);
		$query->bindValue(':salt', $salt, PDO::PARAM_LOB);
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->password = $password;
		$this->salt = $salt;
		User::processEventHandlers('onPasswordChange', $this);
	}
	
	//This method needs revision to confirm new email
    public function setEmail(string $email, int $mode = User::SET_EMAIL_CONFIRM) : void
	{
		if(!User::validateEmail($email))
			throw new UserInvalidEmailException($email);
		if(!User::availableEmail($email))
			throw new UserUnavailableEmailException($email);
		$db = User::getDB();
		if($mode == User::SET_EMAIL_CONFIRM)
		{
			$confirmCode = User::generateConfirmCode();
			$query = $db->prepare('INSERT INTO usersChangeEmail(userID, email, confirmCode) VALUES(:userID, :email, :confirmCode)');
			$query->bindValue(':userID', $this->id, PDO::PARAM_INT);
			$query->bindValue(':email', $email, PDO::PARAM_STR);
			$query->bindValue(':confirmCode', hash(User::config('hash_algorithm'), $confirmCode), PDO::PARAM_STR);
			$query->execute();
			//SEND EMAIL HERE!
			$body = User::config('set_email_confirm_body_template');
			$body = str_replace('[id]', $db->lastInsertId(), $body);
			$body = str_replace('[code]', $confirmCode, $body);
			mail($email, User::config('set_email_confirm_subject'), $body, 'From: '.User::config('set_email_confirm_from'));
		}
		else if($mode == User::SET_EMAIL_DIRECT)
		{
			$query = $db->prepare('UPDATE users SET email=:email WHERE id=:id');
			$query->bindValue(':email', $email, PDO::PARAM_STR);
			$query->bindValue(':id', $this->id, PDO::PARAM_INT);
			$query->execute();
			$this->email = $email;
			User::processEventHandlers('onEmailChange', $this);
		}
		else
			throw new UserInvalidModeException('setEmail()', $mode, 'User::SET_EMAIL_CONFIRM, User::SET_EMAIL_DIRECT');
	}
	
	//Checks $count is a positive integer, then updates the database & member
    public function setFailureCount(int $count) : void
	{
		if(!is_int($count))
			throw new UserIncorrectDatatypeException('setFailureCount()', 1, 'integer', $count);
		if($count < 0)
			throw new UserNegativeValueException('setFailureCount()', $count);
		$db = User::getDB();
		$query = $db->prepare('UPDATE users SET failureCount=:count WHERE id=:id');
		$query->bindValue(':count', $count, PDO::PARAM_INT);
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->failureCount = $count;
	}
	
	//Updates the last failure time to current time in the db and object
    public function setFailureTime(float $time = -1) : void
	{
		if($time == -1)
			$time = gettimeofday(true);
		else
		{
			if(!is_numeric($time))
				throw new UserIncorrectDatatypeException('setFailureTime()', 1, 'numeric', $time);
			if($time < 0)
				throw new UserNegativeTimestampException('setFailureTime()', $time);
			if($time > gettimeofday(true))
				throw new UserFutureTimestampException('setFailureTime()', $time);
		}
		$db = User::getDB();
		$query = $db->prepare('UPDATE users SET failureTime=:time WHERE id=:id');
		$query->bindValue(':time', strval($time));
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
		$this->failureTime = $time;
	}
	
	//Checks if the user is currently in a cooldown due to a potential brute force attack, resets failureCount if
	//if it -was- in cooldown, but the cooldown has expired
    public function loginLimitExceeded() : bool
	{
		if($this->failureCount >= User::config('login_failure_limit'))
		{
			if(gettimeofday(true) - $this->failureTime < User::config('login_failure_cooldown'))
				return true; //Also reset last attempt?
			else
				$this->setFailureCount(0);
		}
		return false;
	}
	
	//Checks if the last login was a permittable number of seconds ago to allow a login attempt, returns true if so
    protected function checkLoginFrequency() : bool
	{
		if(is_null($this->failureTime))
			return true;
		if($this->failureTime == 0)
			return true;
		if(gettimeofday(true) - $this->failureTime < User::config('login_frequency_limit'))
		{
			$this->loginFailure();
			return false;
		}
		return true;
	}
	
	//Checks $password against the stored password; returns true if it matches, false otherwise
    public function checkPassword(string $password) : bool
	{
		if(User::processPassword($password, $this->salt) == $this->password)
			return true;
		return false;
	}
	
	//Logs a failed login attempt, setting failureCount & failureTime appropriately
    public function loginFailure() : void
	{
		if(gettimeofday(true) - $this->failureTime > User::config('login_failure_period'))
			$this->setFailureCount(1);
		else
			$this->setFailureCount($this->failureCount + 1);
		$this->setFailureTime();
		//Check if user has just been forced into brute force lockdown, if so trigger onLockdown callbacks
		if($this->failureCount == User::config('login_failure_limit'))
			User::processEventHandlers('onLockdown', $this);
	}
	
	//Generates a new session key; sends out login cookies; updates the database & members
    public function startSession(int $cookieDuration = 0) : void
	{
        if(count($this->sessions) >= User::config('max_sessions')) {
            //Pull UID and key of oldest session
            $query = User::getDB()->prepare('SELECT * FROM usersSessions WHERE userID = :id ORDER BY active ASC LIMIT 1');
            $query->bindValue(':id', $this->id, PDO::PARAM_INT);
            $query->execute();
            $query->bindColumn('id', $id, PDO::PARAM_INT);
            $query->bindColumn('key', $key, PDO::PARAM_STR);
            $query->fetch(PDO::FETCH_BOUND);

            //Remove oldest session from the DB
            $query = User::getDB()->prepare('DELETE FROM usersSessions WHERE id = :id');
            $query->bindValue(':id', $id, PDO::PARAM_INT);
            $query->execute();

            //Clean now-deleted session data from the active User object
            unset($this->sessions[$key]);
        }
		if(!is_int($cookieDuration) && !ctype_digit($cookieDuration))
			throw new UserIncorrectDatatypeException('startSession()', 1, 'integer', $cookieDuration);
		if($cookieDuration < 0)
			throw new UserNegativeValueException('startSession()', $cookieDuration);
		//Ready session data...
		$sessionKey = User::generateSessionKey();
		$hashedKey = hash(User::config('hash_algorithm'), $sessionKey);
		$sessionIP = $_SERVER['REMOTE_ADDR'];
		//Send session cookies...
		User::sendCookies($this->username, $sessionKey, $cookieDuration);
		//Update database...
		$db = User::getDB();
        $query = $db->prepare('INSERT INTO usersSessions(userID, key, IP, active) VALUES(:id, :key, :IP, :active)');
		$query->bindValue(':key', $hashedKey, PDO::PARAM_STR);
		$query->bindValue(':IP', $sessionIP, PDO::PARAM_STR);
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
        $query->bindValue(':active', time(), PDO::PARAM_INT);
		$query->execute();
		//Add/update session in $sessions array
		$this->sessions[$hashedKey] = $sessionIP;
        User::processEventHandlers('onSessionStart', $this);
	}
	
	//Checks if User has valid login session for the current script; checks if logged in
    public function checkSession(string $sessionKey) : bool
	{
		$hashedKey = hash(User::config('hash_algorithm'), $sessionKey);
		if(array_key_exists($hashedKey, $this->sessions))
            if(strcmp($this->sessions[$hashedKey], $_SERVER['REMOTE_ADDR']) == 0) {
                $query = User::getDb()->prepare('UPDATE usersSessions SET active = :active WHERE userID = :id AND key = :key');
                $query->bindValue(':id', $this->id, PDO::PARAM_INT);
                $query->bindValue(':key', $hashedKey, PDO::PARAM_STR);
                $query->bindValue(':active', time(), PDO::PARAM_INT);
                $query->execute();
                return true;
            }
		return false;
	}
	
    public function endSession(string $sessionKey) : void
	{
		$hashedKey = hash(User::config('hash_algorithm'), $sessionKey);
		//Remove cookies...
		User::removeCookies();
		//Remove database data...
		$db = User::getDB();
		$query = $db->prepare('DELETE FROM usersSessions WHERE userID=:userID AND key=:key');
		$query->bindValue(':userID', $this->id, PDO::PARAM_INT);
		$query->bindValue(':key', $hashedKey, PDO::PARAM_STR);
		$query->execute();
		//Remove current IP entry from $sessions array
		unset($this->sessions[$hashedKey]);
        User::processEventHandlers('onSessionEnd', $this);
	}

    public function generateRequestToken() : string
    {
        $token = random_bytes(User::config('request_token_length'));
		$db = User::getDB();
        $query = $db->prepare('UPDATE users SET requestToken = :token WHERE id = :id');
        $query->bindValue('id', $this->id, PDO::PARAM_INT);
        $query->bindValue('token', $token, PDO::PARAM_LOB);
        $query->execute();
		return base64_encode($token);
    }

    public function getRequestToken() : string
    {
        $db = User::getDB();
        $query = $db->prepare('SELECT requestToken FROM users WHERE id = :id');
        $query->bindValue('id', $this->id, PDO::PARAM_INT);
        $query->execute();
        $query->bindColumn('requestToken', $token, PDO::PARAM_LOB);
        $query->fetch(PDO::FETCH_BOUND);
        if($token === NULL)
            return $this->generateRequestToken();
        return base64_encode($token);
    }

    public function checkRequestToken(string $token) : bool
    {
        return $this->getRequestToken() == $token;
    }

    //Delete this user from the database
    public function remove() : void
	{
		//Call any registered onRemove callbacks, passing the user object
		User::processEventHandlers('onRemove', $this);
		//Prep database...
		$db = User::getDB();
		//Remove the record in the users table...
		$query = $db->prepare('DELETE FROM users WHERE id=:id');
		$query->bindValue(':id', $this->id, PDO::PARAM_INT);
		$query->execute();
	}
	
	//Returns a new User object representing the user currently logged in, determined by cookies
    public static function getCurrent() : ?self
	{
		if(!array_key_exists('username', $_COOKIE))
			return NULL;
		$current = new User($_COOKIE['username'], User::GET_BY_USERNAME);
		if($current->checkSession($_COOKIE['sessionKey']))
			return $current;
		return NULL;
	}
		
	//Adds a new user straight to the database; does not require email validation!
    public static function add(string $username, string $password, string $email) : void
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
		$db = User::getDB();
		$query = $db->prepare('INSERT INTO users(username, password, salt, email, date) VALUES(:username, :password, :salt, :email, :date)');
		$query->bindValue(':username', $username, PDO::PARAM_STR);
		$query->bindValue(':password', User::processPassword($password, $salt), PDO::PARAM_STR);
		$query->bindValue(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
		$query->bindValue(':email', $email, PDO::PARAM_STR);
		$query->bindValue(':date', time(), PDO::PARAM_INT);
		$query->execute();
		//Call any registered onAdd callbacks, passing a new user object representing the added user
		User::processEventHandlers('onAdd', new User(intval($db->lastInsertId())));
	}
	
	//Adds a new user to the usersPending database; sends an email out for confirmation
    public static function addPending(string $username, string $password, string $email) : void
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
		$db = User::getDB();
		$query = $db->prepare('INSERT INTO usersPending(username, password, salt, email, date, confirmCode) VALUES(:username, :password, :salt, :email, :date, :confirmCode)');
		$query->bindValue(':username', $username, PDO::PARAM_STR);
		$query->bindValue(':password', User::processPassword($password, $salt), PDO::PARAM_STR);
		$query->bindValue(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
		$query->bindValue(':email', $email, PDO::PARAM_STR);
		$query->bindValue(':date', time(), PDO::PARAM_INT);
		$query->bindValue(':confirmCode', hash(User::config('hash_algorithm'), $confirmCode), PDO::PARAM_STR);
		$query->execute();
		//Send confirm email...
		$body = User::config('confirm_body_template');
		$body = str_replace('[id]', $db->lastInsertId(), $body);
		$body = str_replace('[code]', $confirmCode, $body);
		mail($email, User::config('confirm_subject'), $body, 'From: '.User::config('confirm_from'));
	}
	
	//Should this be a single success+act-or-error method similar to login()?
    public static function confirm() : string
	{
		//validate input here..?
		$db = User::getDB();
		$query = $db->prepare('SELECT * FROM usersPending WHERE id = :id');
		$query->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
		$query->execute();
		$query->bindColumn('username', $username, PDO::PARAM_STR);
		$query->bindColumn('password', $password, PDO::PARAM_STR);
		$query->bindColumn('salt', $salt, PDO::PARAM_LOB);
		$query->bindColumn('email', $email, PDO::PARAM_STR);
		$query->bindColumn('date', $date, PDO::PARAM_INT);
		$query->bindColumn('confirmCode', $confirmCode, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		if($username == NULL)
			return User::config('confirm_no_such_id_template');
		if(hash(User::config('hash_algorithm'), $_GET['code']) == $confirmCode)
		{
			//Copy over data to users table...
			$db = User::getDB();
			$query = $db->prepare('INSERT INTO users(username, password, salt, email, date) VALUES(:username, :password, :salt, :email, :date)');
			$query->bindValue(':username', $username, PDO::PARAM_STR);
			$query->bindValue(':password', $password, PDO::PARAM_STR);
			$query->bindValue(':salt', $salt, PDO::PARAM_LOB); //is LOB right..?
			$query->bindValue(':email', $email, PDO::PARAM_STR);
			$query->bindValue(':date', $date, PDO::PARAM_INT);
			$query->execute();
			//Remove entry from usersPending...
			$query = $db->prepare('DELETE FROM usersPending WHERE id = :id');
			$query->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
			$query->execute();
			//Call any registered onAdd callbacks, passing a new user object representing the added user
			User::processEventHandlers('onAdd', new User(intval($db->lastInsertId())));
			return User::config('confirm_success_template');
		}
		return User::config('confirm_incorrect_code_template');
	}
	
	//This method should be called on a page setup to confirm email changes; returns success or error message
    public static function confirmSetEmail() : string
	{
		//validate input here..?
		$db = User::getDB();
		$query = $db->prepare('SELECT * FROM usersChangeEmail WHERE id = :id');
		$query->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
		$query->execute();
		$query->bindColumn('userID', $userID, PDO::PARAM_INT);
		$query->bindColumn('email', $email, PDO::PARAM_STR);
		$query->bindColumn('confirmCode', $confirmCode, PDO::PARAM_STR);
		$query->fetch(PDO::FETCH_BOUND);
		if($email == NULL)
			return User::config('set_email_confirm_no_such_id_template');
		if(hash(User::config('hash_algorithm'), $_GET['code']) == $confirmCode)
		{
			//Update users email in database...
			$query = $db->prepare('UPDATE users SET email=:email WHERE id=:id');
			$query->bindValue(':email', $email, PDO::PARAM_STR);
			$query->bindValue(':id', $userID, PDO::PARAM_INT);
			$query->execute();
			//Remove entry from usersChangeEmail...
			$query = $db->prepare('DELETE FROM usersChangeEmail WHERE id = :id');
			$query->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
			$query->execute();
			User::processEventHandlers('onEmailChange', new User($userID));
			return User::config('set_email_confirm_success_template');
		}
		return User::config('set_email_confirm_incorrect_code_template');
	}
	
	//This function should be called at the -top- of a login page, before any output; it returns
	// either a success message (and logins in the user), or a form (with appropriate errors)
    public static function login() : string
	{
		$username = NULL;
		$password = NULL;
		$error = NULL;
		
		if(isset($_POST['username']))
		{
			//Check if form was filled out completely...
			if($_POST['username'] == '' && $_POST['password'] == '')
				return User::processLoginForm(User::config('login_no_input_error'));
			if($_POST['username'] == '')
				return User::processLoginForm(User::config('login_no_username_error'));
			if($_POST['password'] == '')
				return User::processLoginForm(User::config('login_no_password_error'), $_POST['username']);
			//Check if entered details are valid...
			if(!User::validateUsername($_POST['username']))
				return User::processLoginForm(User::config('login_invalid_username_error'));
			if(!User::validatePassword($_POST['password']))
				return User::processLoginForm(User::config('login_invalid_password_error'), $_POST['username']);
			//Try finding in the user...
			try{
				$user = new User($_POST['username'], User::GET_BY_USERNAME);
			}
			catch(UserNoSuchUserException $e){
				return User::processLoginForm(User::config('login_no_such_username_error'));
			}
			//Check if user is in cooldown
			if($user->loginLimitExceeded())
				return User::processLoginForm(User::config('login_cooldown_error'), $_POST['username']);
			//Check for unnaturally frequent login attempts
			if(!$user->checkLoginFrequency())
				return User::processLoginForm(User::config('login_frequency_error'), $_POST['username']);
			//Check if the passwords match...
			if(!$user->checkPassword($_POST['password']))
			{
				$user->loginFailure();
				return User::processLoginForm(User::config('login_incorrect_password_error'), $_POST['username']);
			}
			//Success...
			if(array_key_exists('cookie_duration', $_POST) && ctype_digit($_POST['cookie_duration']))
				$user->startSession($_POST['cookie_duration']);
			else
				$user->startSession(User::config('cookie_session_length'));
			$user->setFailureCount(0);
			$user->setFailureTime(0);
			return str_replace('[username]', $user->getUsername(), User::config('login_success_template'));
		}
		return User::processLoginForm();
	}
	
	//This function inserts the dynamic elements into the login form template
    protected static function processLoginForm(string $error = '', string $username = '') : string
	{
		$form = User::config('login_form_template');
		$form = str_replace('[error]', $error, $form);
		$form = str_replace('[username]', $username, $form);
		return $form;
	}
	
	//This method should be called at the appropriate point on the registration page to
	// print the form/success message; returns a string containing the form (with errors
	// as necessary) or a success message
    public static function register() : string
	{
		//If form hasn't been posted, return form...
		if(!isset($_POST['username']))
			return User::processRegisterForm();
		//Check if form was filled out completely...
		if($_POST['username'] == '')
			return User::processRegisterForm(User::config('register_no_username_error'), NULL, $_POST['email']);
		if($_POST['email'] == '')
			return User::processRegisterForm(User::config('register_no_email_error'), $_POST['username']);
		if($_POST['password'] == '')
			return User::processRegisterForm(User::config('register_no_password_error'), $_POST['username'], $_POST['email']);
		if($_POST['passwordConfirm'] == '')
			return User::processRegisterForm(User::config('register_no_confirm_password_error'), $_POST['username'], $_POST['email']);
		//Check if entered details are valid...
		if(!User::validateUsername($_POST['username']))
			return User::processRegisterForm(User::config('register_invalid_username_error'), NULL, $_POST['email']);
		if(!User::validateEmail($_POST['email']))
			return User::processRegisterForm(User::config('register_invalid_email_error'), $_POST['username']);
		if(!User::validatePassword($_POST['password']))
			return User::processRegisterForm(User::config('register_invalid_password_error'), $_POST['username'], $_POST['email']);
		//Check if username & email are available...
		if(!User::availableUsername($_POST['username']))
			return User::processRegisterForm(User::config('register_unavailable_username_error'), NULL, $_POST['email']);
		if(!User::availableEmail($_POST['email']))
			return User::processRegisterForm(User::config('register_unavailable_email_error'), $_POST['username']);
		//Ensure passwords match...
		if($_POST['password'] != $_POST['passwordConfirm'])
			return User::processRegisterForm(User::config('register_password_mismatch_error'), $_POST['username'], $_POST['email']);
		//Add user to the usersPending table..
		User::addPending($_POST['username'], $_POST['password'], $_POST['email']);
		//Process any onRegister callbacks, passing them, at present, nothing...
		User::processEventHandlers('onRegister');
		return User::config('register_success_template');
	}
	
	//This function inserts the dynamic elements into the register form template
    protected static function processRegisterForm(?string $error = NULL, ?string $username = NULL, ?string $email = NULL) : string
	{
		$form = User::config('register_form_template');
		$form = str_replace('[error]', $error, $form);
		$form = str_replace('[username]', $username, $form);
		$form = str_replace('[email]', $email, $form);
		return $form;
	}
	
	//Checks that $username follows the pre-defined conventions
    protected static function validateUsername(string $username) : bool
	{
		if(preg_match(User::config('username_regex'), $username))
			return true;
		return false;
	}
	
	//Checkt that $password follws the pre-defined conventions
    protected static function validatePassword(string $password) : bool
	{
		if(preg_match(User::config('password_regex'), $password))
			return true;
		return false;
	}
	
	//Ensures $emails at least -looks- like a real email address
    protected static function validateEmail(string $email) : bool
	{
		if(preg_match(User::config('email_regex'), $email))
			return true;
		return false;
	}
	
	//Checks if $username already exists in database; returns true if it doesn't, otherwise false
    protected static function availableUsername(string $username) : bool
	{
		$db = User::getDB();
		$query = $db->prepare('SELECT COUNT (*) FROM users WHERE username = :username');
		$query->bindValue(':username', $username, PDO::PARAM_STR);
		$query->execute();
		if($query->fetchColumn() == 0)
		{
			$query = $db->prepare('SELECT COUNT (*) FROM usersPending WHERE username = :username');
			$query->bindValue(':username', $username, PDO::PARAM_STR);
			$query->execute();
			if($query->fetchColumn() == 0)
				return true;
		}
		return false;
	}
	
	//Checks if $email already exists in database; returns true if it doesn't, otherwise false
    protected static function availableEmail(string $email) : bool
	{
		$db = User::getDB();
		$query = $db->prepare('SELECT COUNT (*) FROM users WHERE email = :email');
		$query->bindValue(':email', $email, PDO::PARAM_STR);
		$query->execute();
		if($query->fetchColumn() == 0)
		{
			$query = $db->prepare('SELECT COUNT (*) FROM usersPending WHERE email = :email');
			$query->bindValue(':email', $email, PDO::PARAM_STR);
			$query->execute();
			if($query->fetchColumn() == 0)
				return true;
		}
		return false;
	}
	
	//This method salts the password, and then hashes it multiple times
    protected static function processPassword(string $password, $salt) : string
	{
		for($x = 0; $x < User::config('hash_iterations'); $x++)
			$salt = hash(User::config('hash_algorithm'), $password.$salt);
		return $salt;
	}
	
	//Generates a random salt with a pre-determined length
    protected static function generateSalt() : string
	{
		return random_bytes(User::config('salt_length'));
	}
	
	//Generates a random session key with a pre-determined length
    protected static function generateSessionKey() : string
	{
		$key = random_bytes(User::config('session_key_length'));
		return hash(User::config('hash_algorithm'), $key);
	}
	
	//Generates a random confirmation code with a pre-determined length; result is hashed for email/url
    protected static function generateConfirmCode() : string
	{
		$code = random_bytes(User::config('confirm_code_length'));
		return sha1($code);
	}
	
	//Sends out login cookies, with a few pre-defined parameters
    protected static function sendCookies(string $username, string $sessionKey, int $duration) : void
	{
		if($duration > 0)
			$duration += time();
		setcookie('username',
			  $username,
			  $duration,
			  User::config('cookie_path'),
			  User::config('cookie_domain'),
			  false,
			  true);
		setcookie('sessionKey',
			  $sessionKey,
			  $duration,
			  User::config('cookie_path'),
			  User::config('cookie_domain'),
			  false,
			  true);
		$_COOKIE['username'] = $username;
		$_COOKIE['sessionKey'] = $sessionKey;
	}
	
	//Blanks login cookies, and removes them from the $_COOKIE array
    protected static function removeCookies() : void
	{
		setcookie('username', NULL, -1);
		setcookie('sessionKey', NULL, -1);
		$_COOKIE['username'] = NULL;
		$_COOKIE['sessionKey'] = NULL;
	}
	
	//This array holds the valid events that can be hooked as keys, and an array of the attached
	//callbacks as the values
    protected static $events = [
        'preSetup'          => [],
        'postSetup'         => [],
        'onRegister'        => [],
        'onAdd'             => [],
        'onUsernameChange'  => [],
        'onPasswordChange'  => [],
        'onEmailChange'     => [],
        'onLockdown'        => [],
        'onSessionStart'    => [],
        'onSessionEnd'      => [],
        'onRemove'          => [],
    ];
	
	//This method is used by code using the User class to add their own callbacks into various areas of the logic
	//of various methods of User, such as setting up their own database tables, triggers, etc. when User::setupDB
	//is called, or responding to a user being added or removed from the db etc.
    public static function addEventHandler(string $event, $callback) : void
	{
		if(!array_key_exists($event, User::$events))
			throw new DomainException("User::addEventHandler passed an event that does not exist: $event");
		try {
			$reflector = User::getReflector($callback);
		}
		catch(ReflectionException $e) {
			throw new InvalidArgumentException("User::addEventHandler() requires that its second parameter be a function or method callback, was instead passed: $callback", 0, $e);
		}
		if($reflector->getNumberOfRequiredParameters() > 1) //Revise to be specific if any events pass > 1 parameter
			throw new InvalidArgumentException("User::addEventHandler() was passed a callback that requires more parameters than would be passed to it: $callback");
		if(strcmp(get_class($reflector), 'ReflectionMethod') == 0)
		{
			if($reflector->isAbstract())
				throw new InvalidArgumentException("User::addEventHandler() was passed a callback method that was abstract: $callback");
			if(!$reflector->isPublic())
				throw new InvalidArgumentException("User::addEventHandler() was passed a callback method that was not public: $callback");
		}
		User::$events[$event][] = $callback;
	}
	
    protected static function processEventHandlers() : void
	{
		$args = func_get_args();
		$event = array_shift($args);
		foreach(User::$events[$event] as $callback)
		{
			call_user_func_array($callback, $args);
		}
	}

	//This method analyses a variable claimed to be a callback, returning a ReflectionFunction or ReflectionMethod
	//object reflecting the function/method if it is a valid callback, and throwing a BadFunctionCallException otherwise
    protected static function getReflector($callback) : callable
	{
		if(is_array($callback))
		{
			if(is_object($callback[0]))
			{
				$reflect = new ReflectionObject($callback[0]);
			}
			else if(is_string($callback[0]) && preg_match('/^[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*$/', $callback[0]))
			{
				$reflect = new ReflectionClass($callback[0]);
			}
			return $reflect->getMethod($callback[1]);
		}
		else if(is_string($callback))
		{
			if(preg_match('/^[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*$/', $callback))
				return new ReflectionFunction($callback);
			if(preg_match('/^[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*::[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*$/', $callback))
			{
				$parts = explode('::', $callback);
				return new ReflectionMethod($parts[0], $parts[1]);
			}
		}
		throw new BadFunctionCallException('getReflector() could not identify passed value as a valid callback, unable to create a reflector');
	}
	
	//This variable is to ensure configuration is loaded, and is only loaded once
	protected static $configLoaded = false;
	
	//This function loads config from a file, if applicable, and sets $configLoaded to true
    public static function loadConfig(?string $file = NULL, bool $force = false) : void
	{
		//If no attempt has been made to load the config, attempt to load it, and patch it over $configData
		if(!is_bool($force))
			throw new UserInvalidModeException('loadConfig', $force, 'false (don\'t force), true (force)');
		if(User::$configLoaded && !$force)
			return;
		$pairs = NULL;
		$pathRegex = '%^(?:~?/|[A-Z]:[\\\\/]).+%i';
		if($file === NULL)
		{
			$file = User::DEFAULT_CONFIG_FILE;
			if(!preg_match($pathRegex, User::DEFAULT_CONFIG_FILE))
				$file = __DIR__.'/'.$file;
			if(is_file($file) && is_readable($file))
				$pairs = array_change_key_case(parse_ini_file($file));
		}
		else if(!is_file($file))
			throw new UserIncorrectDatatypeException('loadConfig()', 1, 'file path', $file);
		else if(!is_readable($file))
			throw new UserFileUnreadableException('loadConfig()', $file);
		else
			$pairs = array_change_key_case(parse_ini_file($file));
		if($pairs)
		{
			$pairs = array_uintersect_assoc($pairs, User::$configData, create_function(NULL, "return 0;"));
			User::$configData = array_merge(User::$configData, $pairs);
		}
		//Convert relative db_path values to absolute, taking '.' to be the parent directory of User.php
		if(!preg_match($pathRegex, User::$configData['db_path']))
			User::$configData['db_path'] = __DIR__.'/'.User::$configData['db_path'];
		User::$configLoaded = true;
	}
	
	//Method for accessing configuration info
    public static function config(string $key) : string
	{
		User::loadConfig();
		$key = strtolower($key);
		if(array_key_exists($key, User::$configData))
			return User::$configData[$key];
		//Replace with custom exception?
		throw new UserNoSuchConfigParameterException($key);
	}
	
	//This method must be called to setup the database before any other code is called
    public static function setupDB() : void
	{
		$db = User::getDB();
		//Call any registered preSetup callbacks, passing them the open db connection
		User::processEventHandlers('preSetup', $db);
		//Create 'users' table...
		$query = $db->prepare(User::config('db_users_table_schema'));
		$query->execute();
		//Create 'usersPending' table...
		$query = $db->prepare(User::config('db_userspending_table_schema'));
		$query->execute();
		//Create 'usersChangeEmail' table...
		$query = $db->prepare(User::config('db_userschangeemail_table_schema'));
		$query->execute();
		//Create 'usersSessions' table...
		$query = $db->prepare(User::config('db_userssessions_table_schema'));
		$query->execute();
		//Call any registered postSetup callbacks, passing them the open db connection
		User::processEventHandlers('postSetup', $db);
	}

	//This method should always be used when accessing the database, to ensure the db is setup correctly
    public static function getDB() : PDO
	{
		if(User::$db === NULL)
		{
			User::$db = new PDO('sqlite:'.User::config('db_path'));
			User::$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			User::$db->exec('PRAGMA foreign_keys = ON');
		}
		return User::$db;
	}
}

//CLASS SPECIFIC EXCEPTIONS FOLLOW
class UserInvalidModeException extends DomainException {
	public function __construct($method, $mode, $modes) {
		parent::__construct("$method called with invalid mode flag: $mode. Possible modes are: $modes");
	}
}

class UserIncorrectDatatypeException extends InvalidArgumentException {
	public function __construct($method, $param, $type, $data) {
		parent::__construct("$method expected parameter $param to be $type, instead was passed: $data");
	}
}

class UserNegativeValueException extends DomainException {
	public function __construct($method, $value, $expect = 'otherwise') {
		parent::__construct("$method was passed a negative value when expecting $expect: $value");
	}
}

class UserNegativeTimestampException extends UserNegativeValueException {
	public function __construct($method, $time) {
		parent::__construct($method, $time, 'timestamp');
	}
}

class UserFutureTimestampException extends RangeException {
	public function __construct($method, $time) {
		parent::__construct("$method was passed a timestamp greater than the current time when expecting a past time: $time");
	}
}

class UserNoSuchUserException extends OutOfBoundsException {
	public function __construct($uid, $mode = NULL) {
		if($mode !== NULL) {
			if($mode == User::GET_BY_ID)
				$mode = 'id:';
			if($mode == User::GET_BY_USERNAME)
				$mode = 'username:';
		}
		parent::__construct("Requested User does not exist: $mode$uid");
	}
}

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
class UserUnavailableUsernameException extends RuntimeException{
	public function __construct($value){
		parent::__construct('Username \''.$value.'\' already exists in database.');
	}
}
class UserUnavailableEmailException extends RuntimeException{
	public function __construct($value){
		parent::__construct('Email \''.$value.'\' already exists in database.');
	}
}

class UserFileUnreadableException extends RuntimeException {
	public function __construct($method, $file) {
		parent::__construct("$method was unable to read the specified file: $file");
	}
}

class UserNoSuchConfigParameterException extends DomainException {
	public function __construct($key) {
		parent::__construct("Attempted to access non-existent config parameter: $key");
	}
}

?>
