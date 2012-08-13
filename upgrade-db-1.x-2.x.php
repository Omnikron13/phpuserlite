<?php
// This is a quick'n'dirty script to patch existing databases created with 1.x
// to the new (default) schema from 2.x while preserving existing data. Set
// $dbpath below to the path to the database file you want to patch and run the
// script

$dbpath = '';

// Patchy patch patch...
$interactive = false;
if(strcmp($dbpath, '') == 0)
    $interactive = true;
if($interactive)
	echo "No path specified for the database, assuming CLI, going interactive...\n";
while($interactive)
{
    echo "Please enter the full path to the database file to be patched: ";
    fscanf(STDIN, "%s\n", $dbpath);
    if(is_file($dbpath) && is_readable($dbpath))
        break;
    echo "Entered path either didn't point to a file, or pointed to a file PHP was unable to read.\n";
}
echo "Opening sqlite:$dbpath...\n";
$db = new PDO('sqlite:'.$dbpath);
print_r($db);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
echo "Ensuring foreign keys are off while patching the users table...\n";
$db->exec('PRAGMA foreign_keys = OFF');
echo "Shifting the users table to a temporary location...\n";
$db->exec('ALTER TABLE users RENAME TO users_old');
echo "Created a new users table from the (default) 2.x schema...\n";
$db->exec('CREATE TABLE users(id INTEGER PRIMARY KEY,
                              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                              password TEXT NOT NULL,
                              salt BLOB NOT NULL,
                              email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                              date INTEGER NOT NULL,
                              sessionKey TEXT,
                              sessionIP TEXT,
                              failureCount INTEGER,
                              failureTime REAL)');
echo "Copying the data from the old to the new users table...\n";
$db->exec('INSERT INTO users (id, username, password, salt, email, date, sessionKey, sessionIP) SELECT * FROM users_old');
echo "Nuking the temporary table...\n";
$db->exec('DROP TABLE users_old');

?>
