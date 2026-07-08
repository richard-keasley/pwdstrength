<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="author" content="Richard Keasley">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Demonstration of password strength">
<title>password strength</title>
<style>
table {
	border-collapse: collapse;
}
table td {
	border: 1px solid #eee;
	padding: 0.2em 0.4em;
}
table thead td {
	background: #FEF;
	font-weight: bold;
}
</style>
</head>

<body style="font-size:12pt;font-family:sans-serif;">

<form method="POST">
<?php 
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/pwdstrength.php';
use basecamp\pwdstrength;

class htmtable implements \stringable {

private $tbody = [];

function __tostring() {
	$tbody = '';
	$thead = '';
	foreach($this->tbody as $rowkey=>$row) {
		if(!$rowkey) {
			$thead .= '<tr>';
			foreach(array_keys($row) as $colkey) {
				$thead .= "<td>{$colkey}</td>";
			}
			$thead .= '</tr>';
		}
		
		$tbody .= '<tr>';
		foreach($row as $cell) {
			$tbody .= "<td>{$cell}</td>";
		}
		$tbody .= '</tr>';
	}
	
	$html = '<table>';
	$html .= "<thead>{$thead}</thead>";
	$html .= "<tbody>{$tbody}</tbody>";
	$html .= '</table>';
	return $html;
}

function addrow($arr) {
	$tr = [];
	foreach($arr as $colkey=>$td) {
		if(is_array($td)) $td = implode(', ', $td);
		$tr[$colkey] = $td;
	}
	$this->tbody[] = $tr;	
}

}



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
<?php
$table = new htmtable;

$arr = pwdstrength::calculate($postvals['password'], $postvals['username']);
$arr = ['password'=>$postvals['password']] + $arr;
$table->addrow($arr);	

$tries = [
	'password',
	'password-ijbkadcihvbwegwe',
	'ijbkadcihvbwegwe',
	'short',
	'random',
	'random-abc',
	'random-731',
	'thr33--RANDOM--words',
];
foreach($tries as $password) {
	$arr = pwdstrength::calculate($password, $postvals['username']);
	$arr = ['password'=>$password] + $arr;
	$table->addrow($arr);	
}
echo $table;

?>
</body>
</html>
