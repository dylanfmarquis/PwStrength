from setuptools import setup, find_packages

setup(name='PwStrength',
      version='0.1.0',
      author='Dylan F. Marquis',
      url='https://github.com/dylanfmarquis/PwStrength',
      license='MIT',
      packages=find_packages(),
      install_requires=['pyenchant==1.6.11']
      )
