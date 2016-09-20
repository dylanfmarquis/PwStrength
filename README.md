# PwStrength
Wolfram Style Password Strength Test

Fork from MetroWind's (Darksair) Gist: https://gist.github.com/MetroWind/1514997

Dependancies
----
Enchant - Enchant spellchecking system

Setup
----
```bash
export PYTHONPATH=$PYTHONPATH:/home/foo/PwStrength
```
##Examples
```python
>>> from PwStrength import *
>>>
>>> passwd = "Secret123"
>>>
>>> PwStrength(passwd)
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
```
###prettyPasswordEnumeration
prettyPasswordEnumeration takes 2 arguements, the number of passwords (2 raised to the power of the
password's entropy and the number of guesses a given machine could guess in 1 second. In the case
of the example above, it's 100,000 guesses per second.
###Password entropy derivation
The password entropy calculation is based on NIST SP 800-63
http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf

Changes
----
Added English dictionary word detection

Added Wolfram "Extra Criteria"

Added password entropy

Added number of passwords

Added password enumeration time
