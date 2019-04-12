# PwStrength
Wolfram Style Password Strength Test

Fork from MetroWind's (Darksair) Gist: https://gist.github.com/MetroWind/1514997

## Dependancies

Enchant - Enchant spellchecking system

## Setup
```bash
pip install PwStrength
```
## Usage
```python
>>> from PwStrength import *
>>>
>>> passwd = "Secret123"
>>>
>>> pwStrength(passwd)
>>> # 49
>>>
>>> prettyScore(passwd)
>>> # Weak
>>>
>>> passwordEntropy(passwd)
>>> # 25.6
>>>
>>> prettyPasswordEnumeration(passwordNumber(passwd), 100000)
>>> # 7.91 minutes
>>>
>>> passwordExposition(passwd)
>>> True
>>>
>>> prettyPasswordExposition(passwd)
>>> This password has been exposed in a data breach
```
### prettyPasswordEnumeration
prettyPasswordEnumeration takes 2 arguements, the number of passwords (2 raised to the power of the
password's entropy and the number of guesses a given machine could guess in 1 second. In the case
of the example above, it's 100,000 guesses per second.

### Password entropy derivation
The password entropy calculation is based on NIST SP 800-63-2
https://csrc.nist.gov/publications/detail/sp/800-63/2/archive/2013-08-29

### Password exposition check
The passwordExposition leverages the API from haveibeenpwned.com. The API uses a k-Anonymity model, which
removes the need to send the entire password hash to haveibeenpwned.com. PwStrength sends the first five
characters of a SHA-1 hash, haveibeenpwned returns all of the suffixes of exposed passwords in it's 
database. If PwStrength matches the supplied password to one found in the API's return, it will return
True. Further information regarding the k-Anonymity model employed by haveibeenpwned can be found in
the article below.
https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/

### prettyPasswordExposition
prettyPasswordExposition takes the result of passwordExposition, returning a string indicating the
exposure of the password.

Changes
----
Added English dictionary word detection

Added Wolfram "Extra Criteria"

Added password entropy

Added number of passwords

Added password enumeration time

Added password exposition check
