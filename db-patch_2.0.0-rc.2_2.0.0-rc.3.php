<?php

require_once('User.php');

$db = new PDO('sqlite:'.User::config('db_path'));
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$db->exec('CREATE TEMP TABLE users_backup AS SELECT * FROM users');
$db->exec('DROP TABLE users');
$db->exec(User::config('db_users_table_schema'));
$db->exec('INSERT INTO users(id, username, password, salt, email, date, sessionKey, sessionIP, failureCount, failureTime) SELECT * FROM users_backup');

?>
