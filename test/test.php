<?php
require "/f5/wsabey/protected/User.php";
class UserTest extends User
{
	public static function testLoadConfig ()
	{
		echo "<h1>Testing loadConfig()...</h1>";
		try
		{
			echo "<p>Testing absent config file:</p>";
			User::loadConfig('/f5/wsabey/protected/absent.cfg');
			echo "<p class='fail'>Failed: Exception not thrown on absent config file.</p>";
		}
		catch(InvalidArgumentException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		try
		{
			echo "<p>Testing unreadable config file:</p>";
			User::loadConfig('/f5/wsabey/protected/unreadable.cfg');
			echo "<p class='fail'>Failed: Exception not thrown on unreadable config file.</p>";
		}
		catch(InvalidArgumentException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		try
		{
			echo "<p>Testing incorrect \$force value: 'foo'.</p>";
			User::loadConfig('/f5/wsabey/protected/test.cfg', 'foo');
			echo "<p class='fail'>Failed: Exception not thron on invalid force value.</p>";
		}
		catch(InvalidArgumentException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		echo "<p>Testing present config file:</p>";
		User::loadConfig('/f5/wsabey/protected/test.cfg');
		echo "<p class='pass'>Passed.</p>";
	}

	public static function testSetupDB ()
	{
		echo "<h1>Testing setupDB()...</h1>";
		User::setupDB();
		echo "<p>Setup successful.</p>";
	}

	public static function testAdd ()
	{
		echo "<h1>Testing add()...</h1>";
		try
		{
			echo "<p>Testing invalid username: 'Test Name'</p>";
			User::add("Test Name", "testpassword", "test@testing.com");
			echo "<p class='fail'>Failed: Exception not thrown on invalid username.</p>";
		}
		catch(UserInvalidUsernameException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		try
		{
			echo "<p>Testing invalid password: 'test'</p>";
			User::add("Test", "test", "test@testing.com");
			echo "<p class='fail'>Failed: Exception not thrown on invalid password.</p>";
		}
		catch(UserInvalidPasswordException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		try
		{
			echo "<p>Testing invalid email: 'test'</p>";
			User::add("Test", "testpassword", "test");
			echo "<p class='fail'>Failed: Exception not thrown on invalid email.</p>";
		}
		catch(UserInvalidEmailException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		echo "<p>Testing valid user:</p>";
		User::add("Test", "testpassword", "test@testing.com");
		echo "<p class='pass'>Passed.</p>";
		try
		{
			echo "<p>Testing duplicate username:</p>";
			User::add("Test", "testpassword", "test2@testing.com");
			echo "<p class='fail'>Failed: Exception not thrown on duplicate username.</p>";
		}
		catch(UserUnavailableUsernameException $e)
		{
			echo "<p class='pass'>Passed.</p>";
		}
		try
		{
			echo "<p>Testing duplicate email:</p>";
			User::add("Test2", "testpassword", "test@testing.com");
			echo "<p class='fail'>Failed: Exception not thrown on duplicate email.</p>";
		}
		catch(UserUnavailableEmailException $e)
		{
			echo "<p class='pass'>Passed</p>";
		}
	}
}
set_exception_handler (function ($e) {
	print "<p class='fail'>Fail: Unexpected exception thrown: ".get_class ($e)."</p>";
	print "<p>".$e->getMessage ()."</p>";
});
?>
<!DOCTYPE html>
<html>
<head>
<link rel='stylesheet' href='/css/test' type='text/css' />
</head>
<body>
<?php
UserTest::testLoadConfig();
$dbPath = User::config ('db_path');
if (is_file ($dbPath))
	unlink ($dbPath);
UserTest::testSetupDB();
UserTest::testAdd();
?>
</body>
</html>