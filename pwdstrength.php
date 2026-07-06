<?php
namespace basecamp;

/**
 * Password Strength - A class to calculate and evaluate password strength
 */
class pwdstrength {
	
const encoding = 'UTF-8';
const charscore = 5;
	
/**
 * Calculate the strength of a password
 *
 * @param string $password The password to evaluate
 * @param string $username Optional username to check if it's included in password
 * @return array An associative array containing:
 *      - strength: Strength level (0-5)
 *      - label: Human-readable strength label
 *      - percentage: Strength as a percentage (0-100)
 *      - feedback: Array of feedback messages
 *      - scores: array of scores from each test 
 */
public static function calculate($password, $username=null) {
	
	// Normalize inputs (NFC) to treat composed/decomposed characters consistently
	$password = self::normalize((string) $password);
	$username = $username !== null ? self::normalize((string) $username) : null;
	
	$checknames = [
		'length', 
		'lowercase', 'uppercase', 'numbers', 'symbols',
		'username', 'repeated', 'sequential', 'patterns',
	];
	$scores = [];
	$feedback = [];
	foreach($checknames as $checkname) {
		$res = self::{"check_{$checkname}"}($password, $username);
		$check_score = $res['score'] ?? 0;
		$check_feedback = $res['feedback'] ?? null;
		if($check_feedback) $feedback[$checkname] = $check_feedback;
		$scores[$checkname] = $check_score;
		# echo $checkname; print_r($res);
	}
		
	// Normalize score to 0-100 range
	$percentage = max(0, min(100, array_sum($scores)));
	// strength score range 0-5
	$strengthLevel = (int) round($percentage / 20);

	return [
		'entropy' => self::entropy($password),
		'strength' => $strengthLevel,
		'label' => self::getLabel($strengthLevel),
		'percentage' => $percentage,
		'feedback' => $feedback,
		'scores' => $scores,
	];
}

/**
 * Get the label for a given password strength
 * @param int $strength The strength level (0-5)
 * @return string The strength label
 */
public static function getLabel($strength) {
	return match((int) $strength) {
		0 => 'Very Weak',
		1 => 'Weak',
		2 => 'Fair',
		3 => 'Good',
		4 => 'Strong',
		5 => 'Very Strong',
		default => 'Unknown'
	};
}

/**
 * Check if a password meets minimum security requirements
 *
 * @param string $password
 * @param string $username Optional username to check against
 * @param int $minStrength Minimum strength required (0-5), default is 2 (Fair)
 * @return bool
 */
public static function isSufficient($password, $username=null, $minStrength=2) {
	$result = self::calculate($password, $username);
	return $result['strength'] >= $minStrength;
}

public static function entropy(string $password) : float {
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
    # echo "$strlen $size ";
	   
	// Entropy = log2(charset_size ^ password_length)
	return ($size && $strlen) ? log($size ** $strlen, 2) : 0;	
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

private static function check_length(string $password) : array {
	// Check password length (characters, not bytes)
	$length = mb_strlen($password, self::encoding);
	$retval = ['score' => min(75, ($length - 4) * self::charscore)];
	if($length < 6) $retval['feedback'] = 'Make password longer';
	return $retval;
}

private static function check_lowercase(string $password) : array {
	// Check for lowercase letters (Unicode-aware)
	$success = ['score' => 4];
	$fail = ['feedback' => 'Add lowercase letters to your password'];
	return preg_match('/\p{Ll}/u', $password) ? $success : $fail ;
}

private static function check_uppercase(string $password) : array {
	// Check for uppercase letters (Unicode-aware)
	$success = ['score' => 4];
	$fail = ['feedback' => 'Add uppercase letters to your password'];
	return preg_match('/\p{Lu}/u', $password) ? $success : $fail ;
}

private static function check_numbers(string $password) : array {
	// Check for numbers (Unicode digits)
	$success = ['score' => 8];
	$fail = ['feedback' => 'Add numbers to your password'];
	return preg_match('/\p{Nd}/u', $password) ? $success : $fail ;
}

private static function check_symbols(string $password) : array {
	// Check for special characters (punctuation, symbols, separators)
	$success = ['score' => 12];
	$fail = ['feedback' => 'Add punctuation or symbols to your password'];
	return preg_match('/[\p{P}\p{S}\p{Z}]/u', $password) ? $success : $fail ;
}

private static function check_repeated(string $password) : array {
	// Check for repeated characters (Unicode-aware)
	$success = [];
    $fail = [
		'score' => -15,
		'feedback' => 'Avoid repeated characters (e.g., "aaa")'
	];
	return preg_match('/(.)\1{2,}/u', $password) ? $fail : $success ;
}

private static function check_sequential(string $password) : array {
	// Check for sequential characters (Unicode-aware)
	$password = mb_strtolower(self::normalize((string) $password), self::encoding);
	$len = mb_strlen($password, self::encoding);
	
	// Extract characters into array
	$chars = [];
	for($i = 0; $i < $len; $i++) {
		$chars[] = mb_substr($password, $i, 1, self::encoding);
	}
	
	$fail = false;
	for($i = 0; $i < count($chars) - 2; $i++) {
		$sequence = mb_substr($password, $i, 3, self::encoding);
		$o1 = self::char_ord($sequence[0]);
		$o2 = self::char_ord($sequence[1]);
		$o3 = self::char_ord($sequence[2]);
		if($o1===0 || $o2===0 || $o3===0) continue;

		// Ascending sequence
		if($o1 + 1 === $o2 && $o2 + 1 === $o3) $fail = true;
		// Descending sequence
		if($o1 - 1 === $o2 && $o2 - 1 === $o3) $fail = true;
		
		if($fail) {
			return [
				'score' => -15,
				'feedback' => "Avoid sequential characters ('{$sequence}')",
			];
		}
	}

    return [];
}

private static $dictionary = null;

private static function check_patterns(string $password) : array {
	// Check for common password patterns (Unicode-aware lowercase check)
    $password = mb_strtolower(self::normalize((string) $password), self::encoding);

	if(!self::$dictionary) {
		self::$dictionary = [];
		$filename = __DIR__ . '/dictionary.txt';
		foreach(file($filename) as $row) {
			$row = trim($row);
			if($row) self::$dictionary[] = $row;	
		}
	}
	
	foreach(self::$dictionary as $pattern) {
		if(mb_strpos($password, $pattern, 0, self::encoding) !== false) {
			return [
				'score' => -10 - (strlen($pattern) * self::charscore),
				'feedback' => "Avoid common patterns like '{$pattern}'",
			];
		}
	}
	
	return [];
}

private static function check_username(string $password, $username=null) : array {
	// Check if username is included in the password (Unicode-aware)	
	
	if(empty($username)) return [];

	// Ensure both strings are normalized and lowercased 
	$password = mb_strtolower(self::normalize($password), self::encoding);
	$username = mb_strtolower(self::normalize((string) $username), self::encoding);
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
