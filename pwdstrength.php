<?php
namespace basecamp;

/**
 * Password Strength - A class to calculate and evaluate password strength
 */
class pwdstrength {
	
const encoding = 'UTF-8';
	
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
	$percentage = array_sum($scores);
	$percentage = max(0, min(100, $percentage));
	$strengthLevel = (int) round($percentage/20);

	return [
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

private static function check_username(string $password, $username=null) : array {
	// Check if username is included in the password (Unicode-aware)	
	
	if(empty($username)) return [];

	// Ensure both strings are normalized and lowercased 
	$password = mb_strtolower(self::normalize($password), self::encoding);
	$username = mb_strtolower(self::normalize((string) $username), self::encoding);

	// Check if username appears as a substring (multibyte-safe)
	if(mb_strpos($password, $username, 0, self::encoding) !== false) {
		return [
			'feedback' => 'Password should not contain your username',
			'score' => -30,
		];	
	}

	// Check if significant portions of username appear
	$check_len = 3; // check length
	$user_len = mb_strlen($username, self::encoding);
	for($i=0; $i<$user_len; $i++) {
		$part = mb_substr($username, $i, $check_len, self::encoding);
		$part_len = mb_strlen($part, self::encoding);
		if($part_len<$check_len) continue;
		if(mb_strpos($password, $part, 0, self::encoding) !== false) {
			return [
				'feedback' => 'Password should not contain part of your username',
				'score' => -15,
			];
		}
	}

	return [];
}

private static function check_length(string $password) : array {
	// Check password length (characters, not bytes)
	$length = mb_strlen($password, self::encoding);
	$retval = ['score' => min(75, ($length - 2) * 3)];
	if($length < 6) $retval['feedback'] = 'Make password longer';
	return $retval;
}

private static function check_lowercase(string $password) : array {
	// Check for lowercase letters (Unicode-aware)
	$success = ['score' => 8];
	$fail = ['feedback' => 'Add lowercase letters to your password'];
	return preg_match('/\p{Ll}/u', $password) ? $success : $fail ;
}

private static function check_uppercase(string $password) : array {
	// Check for uppercase letters (Unicode-aware)
	$success = ['score' => 8];
	$fail = ['feedback' => 'Add uppercase letters to your password'];
	return preg_match('/\p{Lu}/u', $password) ? $success : $fail ;
}

private static function check_numbers(string $password) : array {
	// Check for numbers (Unicode digits)
	$success = ['score' => 12];
	$fail = ['feedback' => 'Add numbers to your password'];
	return preg_match('/\p{Nd}/u', $password) ? $success : $fail ;
}

private static function check_symbols(string $password) : array {
	// Check for special characters (punctuation, symbols, separators)
	$success = ['score' => 16];
	$fail = ['feedback' => 'Add punctuation or symbols to your password'];
	return preg_match('/[\p{P}\p{S}\p{Z}]/u', $password) ? $success : $fail ;
}

private static function check_repeated(string $password) : array {
	// Check for repeated characters (Unicode-aware)
	$success = [];
    $fail = [
		'score' => -10,
		'feedback' => 'Avoid repeated characters (e.g., "aaa")'
	];
	return preg_match('/(.)\1{2,}/u', $password) ? $fail : $success ;
}

private static function check_sequential(string $password) : array {
	// Check for sequential characters (Unicode-aware)
	$success = [];
    $fail = [
		'score' => -10,
		'feedback' => 'Avoid sequential characters (e.g., "abc", "123")'
	];
	
	$password = mb_strtolower(self::normalize((string) $password), self::encoding);
	$len = mb_strlen($password, self::encoding);
	
	// Extract characters into array
	$chars = [];
	for($i = 0; $i < $len; $i++) {
		$chars[] = mb_substr($password, $i, 1, self::encoding);
	}

	for($i = 0; $i < count($chars) - 2; $i++) {
		$o1 = self::char_ord($chars[$i]);
		$o2 = self::char_ord($chars[$i+1]);
		$o3 = self::char_ord($chars[$i+2]);
		if($o1===0 || $o2===0 || $o3===0) continue;

		// Ascending sequence
		if ($o1 + 1 === $o2 && $o2 + 1 === $o3) return $fail;
		// Descending sequence
		if ($o1 - 1 === $o2 && $o2 - 1 === $o3) return $fail;
	}

    return $success;
}

private static function check_patterns(string $password) : array {
	// Check for common password patterns (Unicode-aware lowercase check)
	$success = [];
    $fail = [
		'score' => -20,
		'feedback' => 'Avoid common patterns like "password", "123456", "qwerty"',
	];

	$commonPatterns = [
		'password',
		'123456',
		'12345678',
		'qwerty',
		'abc123',
		'111111',
		'admin',
		'letmein',
		'welcome',
		'monkey',
		'1234567',
		'dragon',
		'master',
		'sunshine',
		'princess',
		'qazwsx',
	];
	$password = mb_strtolower(self::normalize((string) $password), self::encoding);

	foreach($commonPatterns as $pattern) {
		if(mb_strpos($password, $pattern, 0, self::encoding) !== false) {
			return $fail;
		}
	}
	return $success;
}

}
