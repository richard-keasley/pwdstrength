<?php

/**
 * Password Entropy Calculator
 * 
 * Calculates the entropy (strength) of a password based on character set
 * diversity and length.
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
        $passwordLength = strlen($password);
        
        if ($charsetSize === 0 || $passwordLength === 0) {
            return 0;
        }
        
        // Entropy = log2(charset_size ^ password_length)
        return log($charsetSize ** $passwordLength, 2);
    }
    
    /**
     * Get the character set size based on character types in the password
     *
     * @param string $password The password to analyze
     * @return int The size of the character set
     */
    private function getCharsetSize(string $password): int
    {
        $charsetSize = 0;
        
        // Check for lowercase letters (26 possible characters)
        if (preg_match('/[a-z]/', $password)) {
            $charsetSize += 26;
        }
        
        // Check for uppercase letters (26 possible characters)
        if (preg_match('/[A-Z]/', $password)) {
            $charsetSize += 26;
        }
        
        // Check for digits (10 possible characters)
        if (preg_match('/[0-9]/', $password)) {
            $charsetSize += 10;
        }
        
        // Check for special characters (32 common special characters)
        if (preg_match('/[!@#$%^&*()\-_=+\[\]{};:\'",.<>?\/\\|`~]/', $password)) {
            $charsetSize += 32;
        }
        
        // Check for other special characters
        if (preg_match('/[^\w!@#$%^&*()\-_=+\[\]{};:\'",.<>?\/\\|`~\s]/', $password)) {
            $charsetSize += 10;
        }
        
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
        
        return [
            'password_length' => strlen($password),
            'entropy_bits' => round($entropy, 2),
            'strength' => $strength,
            'charset_size' => $this->getCharsetSize($password),
            'has_lowercase' => (bool) preg_match('/[a-z]/', $password),
            'has_uppercase' => (bool) preg_match('/[A-Z]/', $password),
            'has_digits' => (bool) preg_match('/[0-9]/', $password),
            'has_special_chars' => (bool) preg_match('/[^\w\s]/', $password),
        ];
    }
}
