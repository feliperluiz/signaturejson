import sys
from distutils.core import setup

install_requires = [
    'eight>=0.4.2',
    'iso8601>=0.1.11',
    'requests>=2.14.2',
]

if sys.version_info[0] == 2:
    install_requires.append('enum34>=1.1.6')

tests_requires = [
    'pytest>=3.0.7',
    'pytz>=2017.2',
]

setup(
    name='kkmip',
    version='0.9.0',
    packages=[
        'kkmip',
        'kkmip.types',
        'kkmip.ttv',
    ],
    license='MIT License',
    install_requires=install_requires,
    tests_requires=tests_requires,
    # pip does not interpret tests_requires but can interpret extras_require.
    # These can be installed with pip install -e .[test]
    extras_require={'test': tests_requires},
)
