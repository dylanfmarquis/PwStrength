# PwStrength
Wolfram Style Password Strength Test

Fork from MetroWind's (Darksair) Gist: https://gist.github.com/MetroWind/1514997

## Dependancies

Enchant - Enchant spellchecking system

## Setup
```bash
pip install PwStrength
```
## Example Usage
```python
>>> from PwStrength import *
>>>
>>> passwd = "Secret123"
>>>
>>> pws = PwStrength(passwd)
>>>
>>> pws.stats()
Password Score: 49
Estimated Password Strength: Weak
Password Entropy: 53.587766793481876
Number of Paswords: 1.3537086546263544e+16
Time to Enumeration (default 10 GH/s): 15.667924243360583 days
Password Exposed in a Breach: True
>>>
>>> print(pws.score)
49
>>>
>>> print(pws.pretty_score)
Weak
>>>
>>> print(pws.entropy)
53.58
>>>
>>> pws.prettyPasswordEnumeration(10000000000)
15.667924243360583 days
>>>
>>> passwordExposure(passwd)
True
>>>
>>> prettyPasswordExposure(passwd)
This password has been exposed in a data breach
```
### prettyPasswordEnumeration
prettyPasswordEnumeration takes hashing rate as an argument. Hashing rate is the number of 
guesses a given machine could guess in 1 second. In the example above, the rate is 10 GH/s.

### Password Entropy Derivation
Entropy is calculated using the following formula:

L = Number of characters in the password
R = Size of the character pool used

E = L * log(R) / log(2)

### Password Exposure Check
The passwordExposure leverages the API from haveibeenpwned.com. The API uses a k-Anonymity model, which
removes the need to send the entire password hash to haveibeenpwned.com. PwStrength sends the first five
characters of a SHA-1 hash, haveibeenpwned returns all of the suffixes of exposed passwords in it's 
database. If PwStrength matches the supplied password to one found in the API's return, it will return
True. Further information regarding the k-Anonymity model employed by haveibeenpwned can be found in
the article below.

https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/

### prettyPasswordExposure
prettyPasswordExposure takes the result of passwordExposure, returning a string indicating the
exposure of the password.

## Disable Automatic Analysis
Analysis functions are run automatically at initialization. This functionality can be disabled, if 
running specific analysis against large datasets.

```python
pws = PwStrength(passwd, auto=False)
```

## Unit Tests
```bash
python -m unittest tests/test.py
```