from setuptools import setup, find_packages

setup(
    name='micropki',
    version='0.1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'micropki = micropki.cli:main',
        ],
    },
    install_requires=[
        'cryptography>=3.0',
    ],
    python_requires='>=3.8',
)