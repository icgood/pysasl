# Copyright (c) 2022 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from setuptools import setup, find_packages

with open('README.md', 'r') as fh:
    readme = fh.read()

with open('LICENSE.md') as fh:
    license = fh.read()

setup(name='pysasl',
      version='1.0.0.rc8',
      author='Ian Good',
      author_email='ian@icgood.net',
      description='Pure Python SASL client and server library.',
      long_description=readme + license,
      long_description_content_type='text/markdown',
      license='MIT',
      url='https://github.com/icgood/pysasl/',
      python_requires='~=3.7',
      include_package_data=True,
      packages=find_packages(),
      install_requires=['typing-extensions'],
      extras_require={'hashing': ['passlib']},
      entry_points={'pysasl.mechanism': [
          'CRAM-MD5 = pysasl.mechanism.crammd5:CramMD5Mechanism',
          'EXTERNAL = pysasl.mechanism.external:ExternalMechanism',
          'LOGIN = pysasl.mechanism.login:LoginMechanism',
          'PLAIN = pysasl.mechanism.plain:PlainMechanism',
          'XOAUTH2 = pysasl.mechanism.oauth:OAuth2Mechanism',
      ]},
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'License :: OSI Approved :: MIT License',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 3.7',
                   'Programming Language :: Python :: 3.8',
                   'Programming Language :: Python :: 3.9',
                   'Programming Language :: Python :: 3.10',
                   'Programming Language :: Python :: 3.11'])
