from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


setup(
    name = 'CuckooByte',
    version = '0.0.1',
    author = '-',
    author_email = '-',
    license = 'MIT',
    description = 'A commandline tool that provides simple pennetration testing capabilities.',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = 'https://github.com/Raphaelvddoel/2IC80',
    py_modules = ['cuckoo_byte', 'functions'],
    packages = find_packages(),
    python_requires='>=3.10',
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    entry_points = '''
        [console_scripts]
        cuckoo=cuckoo_byte:cli
    '''
)