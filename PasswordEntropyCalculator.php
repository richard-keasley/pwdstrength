<?php

/**
 * Password Entropy Calculator
 * 
 * Calculates the entropy (strength) of a password based on character set
 * diversity and length. Adds UTF-8 support using multibyte string functions
 * and Unicode-aware regular expressions.
 */
class PasswordEntropyCalculator
{
    /**
     * Calculate the entropy of a password
     * 
     * Entropy is calculated using the formula: log2(charset_size ^ password_length)
     * where charset_size is the number of possible characters in the password.
     *
     * @param string $password The password to analyze
     * @return float The entropy value in bits
     */
    public function calculateEntropy(string $password): float
    {
        $charsetSize = $this->getCharsetSize($password);
        // Use multibyte-aware length when available
        $passwordLength = function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen($password);
        
        if ($charsetSize === 0 || $passwordLength === 0) {
            return 0;
        }
        
        // Entropy = log2(charset_size ^ password_length)
        return log($charsetSize ** $passwordLength, 2);
    }
    
    /**
     * Get the character set size based on character types in the password
     *
     * This method is Unicode-aware. It counts common ASCII groups precisely
     * (e.g. 26 lowercase Latin letters) and adds heuristic estimates for
     * non-ASCII Unicode letters, punctuation and symbols.
     *
     * @param string $password The password to analyze
     * @return int The size of the character set
     */
    private function getCharsetSize(string $password): int
    {
        $charsetSize = 0;

        // ASCII groups (precise sizes)
        // Check for ASCII lowercase letters (26 possible characters)
        if (preg_match('/[a-z]/', $password)) {
            $charsetSize += 26;
        }

        // Check for ASCII uppercase letters (26 possible characters)
        if (preg_match('/[A-Z]/', $password)) {
            $charsetSize += 26;
        }

        // Check for ASCII digits (10 possible characters)
        if (preg_match('/[0-9]/', $password)) {
            $charsetSize += 10;
        }

        // Check for common ASCII special characters (32 common special characters)
        if (preg_match('/[!@#$%^&*()\-_=+\[\]{};:\\'",.<>?\/\\\\|`~]/', $password)) {
            $charsetSize += 32;
        }

        // Unicode-aware checks for non-ASCII characters
        $hasNonAscii = preg_match('/[^\x00-\x7F]/u', $password);

        if ($hasNonAscii) {
            // If password contains Unicode letters (includes non-Latin scripts)
            if (preg_match('/\p{L}/u', $password)) {
                // We already counted ASCII Latin letters above. For other scripts
                // add a heuristic estimate. Many scripts have tens/hundreds of
                // characters; 100 is a conservative estimate for a single script.
                $charsetSize += 100;
            }

            // Unicode digits/punctuation/symbols
            if (preg_match('/\p{N}/u', $password) && !preg_match('/[0-9]/', $password)) {
                // Non-ASCII digits (rare) - estimate similar to ASCII digits
                $charsetSize += 10;
            }

            if (preg_match('/\p{P}/u', $password) && !preg_match('/[!@#$%^&*()\-_=+\[\]{};:\\'",.<>?\/\\\\|`~]/', $password)) {
                // Non-ASCII punctuation (estimate)
                $charsetSize += 30;
            }

            if (preg_match('/\p{S}/u', $password)) {
                // Symbols (includes emoji, currency symbols, math symbols, etc.)
                // Emoji and symbol space is large; add a larger heuristic.
                $charsetSize += 500;
            }
        }

        // Fallback: if nothing matched, return 0
        return $charsetSize;
    }
    
    /**
     * Get the strength rating of a password based on entropy
     *
     * @param float $entropy The entropy value in bits
     * @return string The strength rating
     */
    public function getStrengthRating(float $entropy): string
    {
        if ($entropy < 28) {
            return 'Very Weak';
        } elseif ($entropy < 36) {
            return 'Weak';
        } elseif ($entropy < 60) {
            return 'Fair';
        } elseif ($entropy < 128) {
            return 'Strong';
        } else {
            return 'Very Strong';
        }
    }
    
    /**
     * Get detailed password strength analysis
     *
     * @param string $password The password to analyze
     * @return array An associative array with entropy, strength rating, and additional info
     */
    public function analyzePassword(string $password): array
    {
        $entropy = $this->calculateEntropy($password);
        $strength = $this->getStrengthRating($entropy);
        $length = function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen($password);

        return [
            'password_length' => $length,
            'entropy_bits' => round($entropy, 2),
            'strength' => $strength,
            'charset_size' => $this->getCharsetSize($password),
            // Use Unicode-aware checks for properties
            'has_lowercase' => (bool) preg_match('/\p{Ll}/u', $password),
            'has_uppercase' => (bool) preg_match('/\p{Lu}/u', $password),
            'has_digits' => (bool) preg_match('/\p{N}/u', $password),
            'has_special_chars' => (bool) preg_match('/[^\p{L}\p{N}\s]/u', $password),
        ];
    }
}
