# pwdstrength
password strength calculator 

## key Features

- Username validation - Checks if the username (or significant portions) appears in the password
- Length checking - Evaluates password length and provides feedback
- Character variety - Checks for lowercase, uppercase, numbers, and special characters
- Pattern detection - Identifies sequential characters (abc, 123) and common weak patterns
- Strength scoring - Rates passwords on a 0-5 scale with percentage

## Main Methods

- calculate($password, $username) - Returns detailed strength analysis
- isSufficient($password, $username, $minScore) - Checks if password meets minimum requirements
- getLabel($score) - Gets human-readable strength label
