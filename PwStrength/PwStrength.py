"""
PwStrength - Password Strength Test
Copyright (C) 2016 Dylan F. Marquis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

__author__      = "Darksair"
__author__      = "Dylan F. Marquis"

from logging import NullHandler
from bitarray import bitarray
from bitarray.util import int2ba, ba2int
import enchant
import hashlib
import math
import re
import requests

class PwStrength(object):

    def __init__(self, password, auto = True):

        self.MASK_LENGTH_8 = int2ba(1, length=8)
        self.MASK_LOWERCASE = int2ba(2, length=8)
        self.MASK_UPPERCASE = int2ba(4, length=8)
        self.MASK_SINGLE_NUMBERAL = int2ba(8, length=8)
        self.MASK_MULTIPLE_NUMBERAL = int2ba(16, length=8)
        self.MASK_SPECIAL_CHAR = int2ba(32, length=8)
        self.MASK_SPEC_CHAR_TOP_ROW = int2ba(64, length=8)
        self.MASK_SPEC_CHAR_ADDITIONAL = int2ba(128, length=8)

        self.password = password
        self.api = 'https://api.pwnedpasswords.com/range/'
        self.criteria = self.scoreExtraCriteria()
        self.characterPools = self.charPools()

        self.score = None
        self.pretty_score = None
        self.entropy = None
        self.exposition = None
        self.pretty_exposition = None
        self.number_of_passwords = None
        self.pretty_enumeration = None

        if auto == True:
            self.score = self.scorePassword()
            self.pretty_score = self.prettyScore()
            self.entropy = self.passwordEntropy()
            self.exposition = self.passwordExposition()
            self.pretty_exposition = self.prettyPasswordExposition()
            self.number_of_passwords = self.passwordNumber()
            self.pretty_enumeration = self.prettyPasswordEnumeration(10000000000)

    def stats(self):

        if self.score:
            print('Password Score: {}'.format(self.score)) 

        if self.pretty_score:
            print('Estimated Password Strength: {}'.format(self.pretty_score))

        if self.entropy:
            print('Password Entropy: {}'.format(self.entropy))

        if self.number_of_passwords:
            print('Number of Paswords: {}'.format(str(self.number_of_passwords)))
        
        if self.pretty_enumeration:
            print('Time to Enumeration (default 10 GH/s): {}'.format(self.pretty_enumeration))

        if self.pretty_exposition:
            print('Password Exposed in a Breach: {}'.format(str(self.exposition)))

    def findSeqChar(self, CharLocs, src):
        """Find all sequential chars in string `src'.  Only chars in
        `CharLocs' are considered. `CharLocs' is a list of numbers.  For
        example if `CharLocs' is [0,2,3], then only src[2:3] is a possible
        substring with sequential chars.
        """
        AllSeqChars = []
        i = 0
        SeqChars = []
        while i < len(CharLocs) - 1:
            if CharLocs[i + 1] - CharLocs[i] == 1 and \
                ord(src[CharLocs[i+1]]) - ord(src[CharLocs[i]]) == 1:
                # We find a pair of sequential chars!
                if not SeqChars:
                    SeqChars = [src[CharLocs[i]], src[CharLocs[i+1]]]
                else:
                    SeqChars.append(src[CharLocs[i+1]])
            else:
                if SeqChars:
                    AllSeqChars.append(SeqChars)
                    SeqChars = []

            i += 1
        if SeqChars:
            AllSeqChars.append(SeqChars)

        return AllSeqChars

    def findDictWord(self):

        CharSubstring = []
        EngDict = enchant.Dict("en_US")
        AlphaStr = ''

        CharSubstring =  re.split(r'[^a-zA-Z0-9]', self.password)

        for SubStr in CharSubstring:
            AlphaStr += SubStr
            if len(SubStr) >= 3:
                if EngDict.check(SubStr):
                    return True

        Position = 0
        Iter = 0

        # Potentially replace with Demunging Function
        for Letter in AlphaStr:
            while Iter <= len(AlphaStr):
                    try:
                        if (EngDict.check(AlphaStr[Position:(Iter-len(AlphaStr))])) and\
                        (len(AlphaStr[Position:(Iter-len(AlphaStr))]) >= 3):
                            return True
                    except:
                        pass
                    Iter += 1

            Iter = 0
            Position += 1

        return False

    def scoreExtraCriteria(self):
        criteria = bitarray('00000000')

        if len(self.password) >= 8:
            criteria = criteria | self.MASK_LENGTH_8

        if re.compile('[a-z]+').findall(self.password):
            criteria = criteria | self.MASK_LOWERCASE

        if re.compile('[A-Z]+').findall(self.password):
            criteria = criteria | self.MASK_UPPERCASE

        if re.compile('[0-9]+').findall(self.password):
            if re.compile('[0-9]{2,}').findall(self.password):
                criteria = criteria | self.MASK_MULTIPLE_NUMBERAL
            else:
                criteria = criteria | self.MASK_SINGLE_NUMBERAL

        #\w can not be used as it represents [a-zA-Z0-9_]
        if re.compile('[^a-zA-Z0-9]').findall(self.password):
            criteria = criteria | self.MASK_SPECIAL_CHAR

            if re.compile('[`~!@#\$%\^&\*\(\)\-_\=\+]+').findall(self.password):
                criteria = criteria | self.MASK_SPEC_CHAR_TOP_ROW

            if re.compile('[^`~!@#\$%\^&\*\(\)\-_\=\+a-zA-Z0-9]').findall(self.password):
                criteria = criteria | self.MASK_SPEC_CHAR_ADDITIONAL

        return criteria

    def charPools(self):
        return self.criteria & ~(self.MASK_LENGTH_8 << 0)

    def extraCriteria(self):
        
        #Score of 0 if length is under 8 chars
        if (ba2int(self.criteria & self.MASK_LENGTH_8)) == 0:
            return 0

        if self.characterPools.count() == 3:
            return 8
        
        if self.characterPools.count() == 4:
            return 10

        return 0

    def scorePassword(self):
        Score = 0
        Length = len(self.password)
        Score += Length * 4

        NUpper = 0
        NLower = 0
        NNum = 0
        NSymbol = 0
        LocUpper = []
        LocLower = []
        LocNum = []
        LocSymbol = []
        CharDict = {}


        for i in range(Length):
            Ch = self.password[i]
            Code = ord(Ch)

            if Code >= 48 and Code <= 57:
                NNum += 1
                LocNum.append(i)
            elif Code >= 65 and Code <= 90:
                NUpper += 1
                LocUpper.append(i)
            elif Code >= 97 and Code <= 122:
                NLower += 1
                LocLower.append(i)
            else:
                NSymbol += 1
                LocSymbol.append(i)

            if not Ch in CharDict:
                CharDict[Ch] = 1
            else:
                CharDict[Ch] += 1

        if NUpper != Length and NLower != Length:
            if NUpper != 0:
                Score += (Length - NUpper) * 2
                # print("Upper case score:", (Length - NUpper) * 2)
            if NLower != 0:
                Score += (Length - NLower) * 2
                # print("Lower case score:", (Length - NLower) * 2)

        if NNum != Length:
            Score += NNum * 4
            # print("Number score:", NNum * 4)
        Score += NSymbol * 6
        # print("Symbol score:", NSymbol * 6)

        # Middle number or symbol
        Score += len([i for i in LocNum if i != 0 and i != Length - 1]) * 2
        # print("Middle number score:", len([i for i in LocNum if i != 0 and i != Length - 1]) * 2)
        Score += len([i for i in LocSymbol if i != 0 and i != Length - 1]) * 2
        # print("Middle symbol score:", len([i for i in LocSymbol if i != 0 and i != Length - 1]) * 2)

        # Letters only?
        if NUpper + NLower == Length:
            Score -= Length
            # print("Letter only:", -Length)
        if NNum == Length:
            Score -= Length
            # print("Number only:", -Length)

        # Repeating chars
        Repeats = 0
        for Ch in CharDict:
            if CharDict[Ch] > 1:
                Repeats += CharDict[Ch] - 1
        if Repeats > 0:
            Score -= int(Repeats / (Length - Repeats)) + 1
            # print("Repeating chars:", -int(Repeats / (Length - Repeats)) - 1)

        if Length > 2:
            # Consequtive letters
            for MultiLowers in re.findall(''.join(["[a-z]{2,", str(Length), '}']), self.password):
                Score -= (len(MultiLowers) - 1) * 2
                # print("Consequtive lowers:", -(len(MultiLowers) - 1) * 2)
            for MultiUppers in re.findall(''.join(["[A-Z]{2,", str(Length), '}']), self.password):
                Score -= (len(MultiUppers) - 1) * 2
                # print("Consequtive uppers:", -(len(MultiUppers) - 1) * 2)

            # Consequtive numbers
            for MultiNums in re.findall(''.join(["[0-9]{2,", str(Length), '}']), self.password):
                Score -= (len(MultiNums) - 1) * 2
                # print("Consequtive numbers:", -(len(MultiNums) - 1) * 2)

            # Sequential letters
            LocLetters = (LocUpper + LocLower)
            LocLetters.sort()
            for Seq in self.findSeqChar(LocLetters, self.password.lower()):
                if len(Seq) > 2:
                    Score -= (len(Seq) - 2) * 2
                    # print("Sequential letters:", -(len(Seq) - 2) * 2)

            # Sequential numbers
            for Seq in self.findSeqChar(LocNum, self.password.lower()):
                if len(Seq) > 2:
                    Score -= (len(Seq) - 2) * 2
                    # print("Sequential numbers:", -(len(Seq) - 2) * 2)


        if self.findDictWord() is True:
            Score -= 20

        Score += self.extraCriteria()

        return Score

    def prettyScore(self):

        if self.score < 0:
            return "Very Weak"

        elif 0 < self.score <= 64:
            return "Weak"

        elif 64 < self.score <= 74:
            return "Fair"

        elif 74 < self.score <= 89:
            return "Strong"

        elif self.score >= 90:
            return "Very Strong"

    def passwordEntropy(self):

        entropy = 0.0
        L = len(self.password)
        poolSize = 0

        if (ba2int(self.characterPools & self.MASK_LOWERCASE) == ba2int(self.MASK_LOWERCASE)):
            poolSize += 26
        
        if (ba2int(self.characterPools & self.MASK_UPPERCASE) == ba2int(self.MASK_UPPERCASE)):
            poolSize += 26

        if ((ba2int(self.characterPools & self.MASK_SINGLE_NUMBERAL) == ba2int(self.MASK_SINGLE_NUMBERAL)) or
            (ba2int(self.characterPools & self.MASK_MULTIPLE_NUMBERAL) == ba2int(self.MASK_MULTIPLE_NUMBERAL))):
            poolSize += 10

        if (ba2int(self.characterPools & self.MASK_SPEC_CHAR_TOP_ROW) == ba2int(self.MASK_SPEC_CHAR_TOP_ROW)):
            #Top row of characters on the keyboard
            poolSize += 16

        if (ba2int(self.characterPools & self.MASK_SPEC_CHAR_ADDITIONAL) == ba2int(self.MASK_SPEC_CHAR_ADDITIONAL)):
            #Rest of special characters visable on keyboard
            poolSize += 16

        return (L*math.log(poolSize)/math.log(2))

    def prettyPasswordEnumeration(self, rate):
        """
        Accepts rate of password hashing (i.e. 100,000 password guesses per second
        """
        sec = self.number_of_passwords/rate
        if sec < 61:
            return "{0} seconds".format(sec)
        else:
            if sec/60 < 61:
                return "{0} minutes".format(round(sec/60,2))
            else:
                if (sec/60) < 25:
                    return "{0} hours".format((sec/60)/60)
                else:
                    if ((sec/60)/60)/24 < 366:
                        return "{0} days".format(((sec/60)/60)/24)
                    else:
                        rem = (((sec/60)/60)/24)/365
                        if rem < 1000001:
                            return "{0} years".format(round(rem,2))
                        else:
                            rem = rem/1000000
                            if rem < 1001:
                                return "{0} million years".format(round(rem,2))
                            else:
                                return "{0} billion years".format(round(rem/1000,2))


    def passwordNumber(self):
        entropy = self.passwordEntropy()

        return math.pow(2, entropy)

    def passwordExposition(self):

        h = hashlib.sha1(self.password.encode('utf-8')).hexdigest()

        prefix = h[0:5].upper()
        suffix = h[5:].upper()

        ret = requests.get('{0}/{1}'.format(self.api,prefix))

        for line in ret.text.split('\n'):

            exposed_suffix = line.split(':')[0]

            if exposed_suffix == suffix:
                return True

        return False

    def prettyPasswordExposition(self):
        response = self.passwordExposition()
        if bool(response):
            return "This password has been exposed in a data breach"
        return "This password was not found in any known data breaches"
