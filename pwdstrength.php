<?php
namespace basecamp;

/**
 * Password Strength - A class to calculate and evaluate password strength
 */
class pwdstrength {
/**
 * Strength levels
 */
const STRENGTH_VERY_WEAK = 0;
const STRENGTH_WEAK = 1;
const STRENGTH_FAIR = 2;
const STRENGTH_GOOD = 3;
const STRENGTH_STRONG = 4;
const STRENGTH_VERY_STRONG = 5;

/**
 * Strength labels
 */
private static $strengthLabels = [
	self::STRENGTH_VERY_WEAK => 'Very Weak',
	self::STRENGTH_WEAK => 'Weak',
	self::STRENGTH_FAIR => 'Fair',
	self::STRENGTH_GOOD => 'Good',
	self::STRENGTH_STRONG => 'Strong',
	self::STRENGTH_VERY_STRONG => 'Very Strong',
];

/**
 * Normalize string to NFC when possible
 */
private static function normalize(string $s): string {
	if (class_exists('Normalizer')) {
		try {
			$s = \Normalizer::normalize($s, \Normalizer::FORM_C);
		} catch (\Throwable $e) {
			// ignore normalization failures and return original
		}
	}
	return $s;
}

/**
 * Get Unicode code point for a single UTF-8 character
 */
private static function utf8_ord(string $char): int {
	$u = mb_convert_encoding($char, 'UCS-4BE', 'UTF-8');
	$val = unpack('N', $u);
	return $val[1] ?? 0;
}

/**
 * Calculate the strength of a password
 *
 * @param string $password The password to evaluate
 * @param string $username Optional username to check if it's included in password
 * @return array An associative array containing:
 *      - score: Strength level (0-5)
 *      - label: Human-readable strength label
 *      - percentage: Strength as a percentage (0-100)
 *      - feedback: Array of feedback messages
 */
public static function calculate($password, $username=null) {
	$score = 0;
	$feedback = [];

	// Normalize inputs (NFC) to treat composed/decomposed characters consistently
	$password = self::normalize((string) $password);
	$username = $username !== null ? self::normalize((string) $username) : null;

	// Check if username is included in password
	if (self::usernameInPassword($password, $username)) {
		$feedback[] = 'Password should not contain your username.';
		$score -= 1.5;
	}

	// Check minimum length (characters, not bytes)
	$length = mb_strlen($password, 'UTF-8');
	if($length <  6 ) $feedback[] = 'Make password longer.';
	if($length >= 6 ) $score += 0.5;
	if($length >= 8 ) $score += 0.5;
	if($length >= 12) $score += 0.5;
	
	// Check for lowercase letters (Unicode-aware)
	if (preg_match('/\p{Ll}/u', $password)) {
		$score += 0.5;
	} else {
		$feedback[] = 'Add lowercase letters to your password.';
	}

	// Check for uppercase letters (Unicode-aware)
	if (preg_match('/\p{Lu}/u', $password)) {
		$score += 0.5;
	} else {
		$feedback[] = 'Add uppercase letters to your password.';
	}

	// Check for numbers (Unicode digits)
	if (preg_match('/\p{Nd}/u', $password)) {
		$score += 0.5;
	} else {
		$feedback[] = 'Add numbers to your password.';
	}

	// Check for special characters (punctuation or symbols)
	if (preg_match('/[\p{P}\p{S}]/u', $password)) {
		$score += 1;
	} else {
		$feedback[] = 'Add special characters (punctuation or symbols) to your password.';
	}

	// Check for repeated characters (Unicode-aware)
	if (preg_match('/(.)\1{2,}/u', $password)) {
		$score -= 0.5;
		$feedback[] = 'Avoid repeated characters (e.g., "aaa").';
	}

	// Check for sequential characters
	if (self::hasSequentialCharacters($password)) {
		$score -= 0.5;
		$feedback[] = 'Avoid sequential characters (e.g., "abc", "123").';
	}

	// Check for common patterns
	if (self::hasCommonPatterns($password)) {
		$score -= 1;
		$feedback[] = 'Avoid common patterns like "password", "123456", "qwerty".';
	}

	// Normalize score to 0-5 range
	$score = max(0, min(5, $score));
	$strengthLevel = (int) round($score);

	// Calculate percentage (0-100)
	$percentage = (int) round(($score / 5) * 100);

	return [
		'score' => $strengthLevel,
		'label' => self::$strengthLabels[$strengthLevel],
		'percentage' => $percentage,
		'feedback' => $feedback,
	];
}

/**
 * Check if username is included in the password (Unicode-aware)
 *
 * @param string $password
 * @param string $username
 * @return bool
 */
private static function usernameInPassword(string $password, $username=null) : bool {
	if(empty($username)) return false;

	// Ensure both strings are normalized and lowercased in UTF-8
	$lowerPassword = mb_strtolower(self::normalize($password), 'UTF-8');
	$lowerUsername = mb_strtolower(self::normalize((string) $username), 'UTF-8');

	// Check if username appears as a substring (multibyte-safe)
	if (mb_strpos($lowerPassword, $lowerUsername, 0, 'UTF-8') !== false) {
		return true;
	}

	// Check if significant portions of username appear (e.g., 3+ characters)
	if (mb_strlen($lowerUsername, 'UTF-8') > 3) {
		$unameLen = mb_strlen($lowerUsername, 'UTF-8');
		for ($i = 0; $i < $unameLen; $i += 3) {
			$part = mb_substr($lowerUsername, $i, 3, 'UTF-8');
			if ($part === '') continue;
			if (mb_strpos($lowerPassword, $part, 0, 'UTF-8') !== false) {
				return true;
			}
		}
	}

	return false;
}

    /**
     * Check if password has sequential characters (Unicode-aware)
     *
     * @param string $password
     * @return bool
     */
    private static function hasSequentialCharacters($password)
    {
        $password = mb_strtolower(self::normalize((string) $password), 'UTF-8');
        $len = mb_strlen($password, 'UTF-8');
        if ($len < 3) return false;

        // Extract characters into array
        $chars = [];
        for ($i = 0; $i < $len; $i++) {
            $chars[] = mb_substr($password, $i, 1, 'UTF-8');
        }

        for ($i = 0; $i < count($chars) - 2; $i++) {
            $o1 = self::utf8_ord($chars[$i]);
            $o2 = self::utf8_ord($chars[$i+1]);
            $o3 = self::utf8_ord($chars[$i+2]);
            if ($o1 === 0 || $o2 === 0 || $o3 === 0) continue;

            // Ascending sequence
            if ($o1 + 1 === $o2 && $o2 + 1 === $o3) return true;
            // Descending sequence
            if ($o1 - 1 === $o2 && $o2 - 1 === $o3) return true;
        }

        return false;
    }

    /**
     * Check for common password patterns (Unicode-aware lowercase check)
     *
     * @param string $password
     * @return bool
     */
    private static function hasCommonPatterns($password)
    {
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

        $lowerPassword = mb_strtolower(self::normalize((string) $password), 'UTF-8');

        foreach ($commonPatterns as $pattern) {
            if (mb_strpos($lowerPassword, $pattern, 0, 'UTF-8') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the strength label for a given score
     *
     * @param int $score The strength score (0-5)
     * @return string The strength label
     */
    public static function getLabel($score)
    {
        $score = (int) $score;
        return self::$strengthLabels[$score] ?? 'Unknown';
    }

    /**
     * Check if a password meets minimum security requirements
     *
     * @param string $password
     * @param string $username Optional username to check against
     * @param int $minScore Minimum score required (0-5), default is 2 (Fair)
     * @return bool
     */
    public static function isSufficient($password, $username = null, $minScore = 2)
    {
        $result = self::calculate($password, $username);
        return $result['score'] >= $minScore;
    }
}
