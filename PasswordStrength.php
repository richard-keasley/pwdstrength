<?php

/**
 * PasswordStrength - A class to calculate and evaluate password strength
 */
class PasswordStrength
{
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
     * Calculate the strength of a password
     *
     * @param string $password The password to evaluate
     * @param string $username Optional username to check if it's included in password
     * @return array An associative array containing:
     *               - score: Strength level (0-5)
     *               - label: Human-readable strength label
     *               - percentage: Strength as a percentage (0-100)
     *               - feedback: Array of feedback messages
     */
    public static function calculate($password, $username = null)
    {
        $score = 0;
        $feedback = [];

        // Check if username is included in password
        if ($username && self::usernameInPassword($password, $username)) {
            $feedback[] = 'Password should not contain your username.';
            $score -= 1.5;
        }

        // Check minimum length
        $length = strlen($password);
        if ($length < 6) {
            $feedback[] = 'Password is too short. Use at least 8 characters.';
        } elseif ($length < 8) {
            $score += 0.5;
        } elseif ($length >= 8 && $length < 12) {
            $score += 1;
        } elseif ($length >= 12) {
            $score += 1.5;
        }

        // Check for lowercase letters
        if (preg_match('/[a-z]/', $password)) {
            $score += 0.5;
        } else {
            $feedback[] = 'Add lowercase letters to strengthen your password.';
        }

        // Check for uppercase letters
        if (preg_match('/[A-Z]/', $password)) {
            $score += 0.5;
        } else {
            $feedback[] = 'Add uppercase letters to strengthen your password.';
        }

        // Check for numbers
        if (preg_match('/[0-9]/', $password)) {
            $score += 0.5;
        } else {
            $feedback[] = 'Add numbers to strengthen your password.';
        }

        // Check for special characters
        if (preg_match('/[!@#$%^&*()_+\-=\[\]{};:\'",.<>?\/\\|`~]/', $password)) {
            $score += 1;
        } else {
            $feedback[] = 'Add special characters (!@#$%^&*) to strengthen your password.';
        }

        // Check for repeated characters
        if (preg_match('/(.)\1{2,}/', $password)) {
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
     * Check if username is included in the password
     *
     * @param string $password
     * @param string $username
     * @return bool
     */
    private static function usernameInPassword($password, $username)
    {
        if (empty($username)) {
            return false;
        }

        $lowerPassword = strtolower($password);
        $lowerUsername = strtolower($username);

        // Check if username appears as a substring
        if (strpos($lowerPassword, $lowerUsername) !== false) {
            return true;
        }

        // Check if significant portions of username appear (e.g., 3+ characters)
        if (strlen($lowerUsername) > 3) {
            $parts = str_split($lowerUsername, 3);
            foreach ($parts as $part) {
                if (strpos($lowerPassword, $part) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if password has sequential characters
     *
     * @param string $password
     * @return bool
     */
    private static function hasSequentialCharacters($password)
    {
        $password = strtolower($password);
        
        // Check for sequential numbers and letters
        for ($i = 0; $i < strlen($password) - 2; $i++) {
            $char1 = ord($password[$i]);
            $char2 = ord($password[$i + 1]);
            $char3 = ord($password[$i + 2]);
            
            if ($char2 === $char1 + 1 && $char3 === $char2 + 1) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check for common password patterns
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

        $lowerPassword = strtolower($password);

        foreach ($commonPatterns as $pattern) {
            if (strpos($lowerPassword, $pattern) !== false) {
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

?>