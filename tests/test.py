from importlib.machinery import SourceFileLoader
import os
import random
import secrets
import sys
import unittest

def get_project_directory():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dirs = current_dir.split(os.sep)
    return os.sep.join(dirs[:dirs.index('PwStrength') + 1])

def import_from_path(path):
    spec = importlib.util.spec_from_file_location("PwStrength", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

PwStrength = SourceFileLoader("PwStrength", f'{get_project_directory()}/PwStrength/__init__.py').load_module()

class Test_PasswordCalculation(unittest.TestCase):

    def test_scoring_entropy_exposure(self):

        # num
        p = PwStrength.PwStrength('0')
        self.assertEqual(p.score, 3)
        self.assertEqual(p.entropy, 3.3219280948873626)


        # 8 char/lower
        p = PwStrength.PwStrength('qwertyui')
        self.assertEqual(p.score, -10)
        self.assertEqual(p.entropy, 37.60351774512874)

        # 8 char/upper/lower
        p = PwStrength.PwStrength('Qwertyui')
        self.assertEqual(p.score, 8)
        self.assertEqual(p.entropy, 45.60351774512874)

        # 8 char/upper/lower
        p = PwStrength.PwStrength('Qwertyui1')
        self.assertEqual(p.score, 36)
        self.assertEqual(p.entropy, 53.587766793481876)

        # 8 char/upper/lower/multi num
        p = PwStrength.PwStrength('Qwertyui13')
        self.assertEqual(p.score, 48)
        self.assertEqual(p.entropy, 59.54196310386876)

        # 8 char/upper/lower/spec char (top row)
        p = PwStrength.PwStrength('Qwertyui!')
        self.assertEqual(p.score, 38)
        self.assertEqual(p.entropy, 54.787165571253055)

        # 8 char/upper/lower/spec char
        p = PwStrength.PwStrength('Awncxqnp]')
        self.assertEqual(p.score, 37)
        self.assertEqual(p.entropy, 54.787165571253055)

        # 8 char/upper/lower/number/spec char
        p = PwStrength.PwStrength('Qwertyui187!')
        self.assertEqual(p.score, 78)
        self.assertEqual(p.entropy, 75.42482662634698)

        # 8 char/upper/lower/number/multi spec char
        p = PwStrength.PwStrength('Qwertyui187!@%')
        self.assertEqual(p.score, 110)
        self.assertEqual(p.entropy, 87.99563106407147)

        # Exposed
        p = PwStrength.PwStrength('password')
        self.assertEqual(p.exposure, True)

        # Not Exposed
        p = PwStrength.PwStrength(secrets.token_urlsafe(20))
        self.assertEqual(p.exposure, False)

if __name__ == "__main__":
    unittest.main()