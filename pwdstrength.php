<?php
namespace basecamp;

/**
 * Password Strength - A class to calculate and evaluate password strength
 */
class pwdstrength {
	
const encoding = 'UTF-8';
const charscore = 5; // used in calculation of penalties in password

private static $dictionary = null;
	
/**
 * Calculate the strength of a password
 *
 * @param string $password The password to evaluate
 * @param string $username Optional username to check if it's included in password
 * @return array An associative array containing:
 *      - strength: Strength level (0-5)
 *      - label: Human-readable strength label
 *      - feedback: Array of feedback messages
 *      - scores: array of scores from each test 
 *      - score: Strength as a percentage (0-100)
 */
public static function calculate($password, $username=null) : array {
	// Normalize inputs (NFC) to treat composed/decomposed characters consistently
	$password = self::normalize((string) $password);
	$username = self::normalize((string) $username);
	
	$checknames = [
		'entropy',
		'username', 'repeated', 'sequential', 'patterns',
	];
	$scores = [];
	$feedback = null;
	foreach($checknames as $checkname) {
		$res = self::{"check_{$checkname}"}($password, $username);
		$check_score = $res['score'] ?? 0;
		$scores[$checkname] = $check_score;
		$check_feedback = $res['feedback'] ?? null;
		if($check_feedback) $feedback = $check_feedback;
	}
	// Normalize score to 0-100 range
	$score = max(0, min(100, array_sum($scores)));
	// strength level for a given password score
	$strength = (int) round($score / 20);
		
	$label = match($strength) {
		0 => 'very weak',
		1 => 'weak',
		2 => 'fair',
		3 => 'good',
		4 => 'strong',
		5 => 'very strong',
		default => '??'
	};

	return [
		'strength' => $strength,
		'label' => $label,
		'feedback' => $feedback,
		'scores' => $scores,
		'score' => $score,
	];
}

/**
 * Check if a password meets minimum security requirements
 *
 * @param string $password
 * @param string $username Optional username to check against
 * @param int $minStrength Minimum strength required (0-5), default is 2 (Fair)
 * @return bool
 */
public static function isSufficient($password, $username=null, $minStrength=2) : bool {
	$result = self::calculate($password, $username);
	return $result['strength'] >= $minStrength;
}

/**
 * Normalize string to NFC when possible
 */
private static function normalize(string $str): string {
	if(class_exists('Normalizer')) {
		try {
			$str = \Normalizer::normalize($str, \Normalizer::FORM_C);
		} 
		catch(\Throwable $ex) {
			// ignore normalization failures and return original
		}
	}
	return $str;
}

/**
 * Get code point for a single character
 */
private static function char_ord(string $char): int {
	$u = mb_convert_encoding($char, 'UCS-4BE', self::encoding);
	$val = unpack('N', $u);
	return $val[1] ?? 0;
}

/*************************************
 * all checks below
 * 
 * https://www.php.net/manual/en/regexp.reference.unicode.php
 *
 * @param string $password
 * @param string $username (optional)
 *
 * all return array elements are optional 
 * @return array[?feedback, ?score]
 **************************************/

private static function check_entropy(string $password, string $username='') : array {
	// pattern, ASCII size, Unicode size
	$chargroups = [
		'lowercase' => ['/\p{Ll}/u', 26, 100],
		'uppercase' => ['/\p{Lu}/u', 26, 80],
		'number' => ['/\p{N}/u', 10, 10],
		'symbol' => ['/[\p{P}\p{S}\p{Z}]/u', 32, 35],
	];
	
	$sizes = [];
	$chars = mb_str_split($password);
	foreach($chars as $char) {
		$chargroup = null;
		foreach($chargroups as $groupname=>$data) {
			if(!$chargroup && preg_match($data[0], $char)) $chargroup = $groupname;
		}
				
		$ascii = preg_match('/[\x00-\x7F]/u', $char);
		
		if($chargroup) {
			if($ascii) {
				$size = $chargroups[$chargroup][1];
				$key = $chargroup;
			}
			else {
				$size = $chargroups[$chargroup][2];
				$key = "{$chargroup}_u";
			}
		}
		else {
			if($ascii) {
				$size = 10;
				$key = 'other';
			}
			else {
				$size = 50;
				$key = 'other_u';
			}
		}
		
		$sizes[$key] = $size;		
		# echo " $char-$key: $size <br>";
	}
	# print_r($sizes);
	
	$size = array_sum($sizes);
	$strlen = mb_strlen($password, self::encoding);
	// entropy = log2(charset_size ^ password_length)
	$entropy = ($size && $strlen) ? log($size ** $strlen, 2) : 0;
	# echo "$password $entropy . <br>";
	
	// normalize entropy to score 0-100
	// tested on spreadsheet
	$score = ($entropy ** 1.3) * 0.3;
	$score = (int) round(min(100, $score));	

// normalize entropy to score 0-100
// Uses logarithmic scaling to reward both length and complexity
// 28 bits = ~30 score, 60 bits = ~70 score, 128+ bits = ~100 score
$score = ($entropy > 0) 
    ? (log($entropy + 1) / log(256)) * 100 
    : 0;
$score = (int) round(min(100, $score));

	
	
	// send feedback
	$feedback = null;
	if($strlen < 6) $feedback = 'Make your password longer';
	if(!$feedback) {
		foreach(array_keys($chargroups) as $groupname) {
			$success = isset($sizes[$groupname]);
			if(!$success) {
				$label = match($groupname) {
					'uppercase', 
					'lowercase' => "{$groupname} letters",
					default => "{$groupname}s"
				};
				$feedback = "Add {$label} to your password";
				break;
			}
		}
	}
		
	$retval = ['score' => $score];
	if($feedback) $retval['feedback'] = $feedback;
	# print_r($retval);
	
	return $retval;
}

private static function check_repeated(string $password, string $username='') : array {
	// Check for repeated characters (Unicode-aware)
	preg_match('/(.)\1{2,}/u', $password, $matches);
	$match = $matches[0] ?? false;
	if(!$match) return [];
	
	$strlen = mb_strlen($match, self::encoding);
	return [
		'score' => -10 - ($strlen * self::charscore),
		'feedback' => 'Avoid repeated characters (e.g. "aaa")'
	];
}

private static function check_sequential(string $password, string $username='') : array {
	// Check for sequential characters (Unicode-aware)
	$password = mb_strtolower($password, self::encoding);
	$strlen = mb_strlen($password, self::encoding);
		
	$maxlen = 0;
	$last_ord = 0;
	$ascending = [];
	$descending = [];
	for($pos = 0; $pos < $strlen; $pos++) {
		$char = mb_substr($password, $pos, 1, self::encoding);
		$ord = self::char_ord($char);
		
		if($ord==($last_ord+1)) $ascending[] = $ord;
		else $ascending = [];
		if($ord==($last_ord-1)) $descending[] = $ord;
		else $descending = [];
		
		$maxlen = max($maxlen, count($ascending), count($descending));
		$last_ord = $ord;
	}
	
	if($maxlen<2) return [];
	
	return [
		'score' => - (($maxlen+1) * self::charscore),
		'feedback' => "Avoid sequential characters (e.g. abc, cba)",
	];
}

private static function check_patterns(string $password, string $username='') : array {
	// Check for common password patterns (Unicode-aware lowercase check)
    $password = mb_strtolower($password, self::encoding);
	
	if(!self::$dictionary) {
		self::$dictionary = [];
		$filename = __DIR__ . '/dictionary.txt';
		$flags = FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES;
		self::$dictionary = file($filename, $flags);
	}
	
	foreach(self::$dictionary as $pattern) {
		if($pattern==$password) {
			return [
				'score' => -50,
				'feedback' => "Avoid using common passwords like '{$pattern}'",
			];
		}
		// short passwords already rejected by entropy
		if(strlen($pattern) < 4) continue;
		if(mb_strpos($password, $pattern, 0, self::encoding) !== false) {
			return [
				'score' => -10 - (strlen($pattern) * self::charscore),
				'feedback' => "Avoid including patterns like '{$pattern}'",
			];
		}
	}
	
	return [];
}

private static function check_username(string $password, string $username='') : array {
	// Check if username is included in the password (Unicode-aware)	
	
	if(empty($username)) return [];

	// Ensure both strings are normalized and lowercased 
	$password = mb_strtolower($password, self::encoding);
	$username = mb_strtolower($username, self::encoding);
	$user_len = mb_strlen($username, self::encoding);
	
	// Check if significant portions of username appear
	for($check_len=$user_len; $check_len>2; $check_len--) {
		for($i=0; $i<$user_len; $i++) {
			$part = mb_substr($username, $i, $check_len, self::encoding);
			$part_len = mb_strlen($part, self::encoding);
			if($part_len<$check_len) continue;
			$start = mb_strpos($password, $part, 0, self::encoding);
			if($start !== false) {
				// found a part
				return ($check_len==$user_len) ? 
					[
						'score' => -20 - ($check_len * self::charscore),
						'feedback' => 'Password should not contain your username',
					] :
					[
						'feedback' => 'Password should not contain part of your username',
						'score' => -5 - ($check_len * self::charscore),
					];
			}
		}
	}

	return [];
}

}
