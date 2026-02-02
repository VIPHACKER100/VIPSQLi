from setuptools import setup, find_packages

setup(
    name="vipsqli-scanner",
    version="2.2.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "aiohttp>=3.9.0",
        "urllib3>=2.0.0",
        "jinja2>=3.1.2",
        "scikit-learn>=1.3.0",
        "flask>=3.0.0",
        "sqlalchemy>=2.0.0",
    ],
    extras_require={
        'full': open('requirements-v2.2.txt').read().splitlines(),
    },
    entry_points={
        'console_scripts': ['vipsqli=sqli_scanner_advanced:main'],
    },
)
