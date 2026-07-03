<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="author" content="Richard Keasley">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Demonstration of password strength">
<title>password strength</title>
</head>

<body style="font-size:12pt;font-family:sans-serif;">

<form method="POST">
<?php 
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/pwdstrength.php';
use basecamp\pwdstrength;

$postvals = [];
$format = '<p><label>%1$s</label> <input style="width:30em" name="%1$s" value="%2$s"></p>';
$keys = ['username', 'password'];
foreach($keys as $key) {
	$val = trim((string) filter_input(INPUT_POST, $key));
	printf($format, $key, $val);
	$postvals[$key] = $val;
}
?>
<p><input type="submit" value="TEST"></p>
</form>
<pre>
<?php
$arr = pwdstrength::calculate($postvals['password'], $postvals['username']);
print_r($arr);

?>
</pre>
</body>
</html>
