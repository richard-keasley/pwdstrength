# pwdstrength
password strength calculator 

## Key features

- Username validation: Checks if the username (or significant portions) appears in the password
- Length checking: Evaluates password length and provides feedback
- Character variety: Checks for lowercase, uppercase, numbers, and special characters
- Pattern detection: Identifies sequential characters (abc, 123) and common weak patterns
- Strength scoring: Rates passwords on a 0-5 scale with percentage

## Main methods

- calculate($password, $username): Returns detailed strength analysis
- isSufficient($password, $username, $minScore): Checks if password meets minimum requirements

## Pattern dictionary

The dictionary used is `Pwdb_top-1000.txt`, forked from 
[Daniel Miessler's SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials).
