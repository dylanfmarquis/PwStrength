from setuptools import setup, find_packages

setup(name = 'PwStrength',
      version = '0.2.0',
      author = 'Dylan F. Marquis',
      author_email = 'dylanfmarquis@dylanfmarquis.com',
      description = 'Wolfram Style Password Strength Test',
      url = 'https://github.com/dylanfmarquis/PwStrength',
      download_url = 'https://github.com/dylanfmarquis/PwStrength/archive/0.2.0.tar.gz',
      packages = ['PwStrength'],
      install_requires = ['pyenchant', 'requests', 'bitarray'],
      keywords = ['password', 'strength', 'testing'],
      )
