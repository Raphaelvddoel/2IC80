from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open('requirements.txt', encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name = 'CuckooByte',
    version = '1.0.0',
    author = '-',
    author_email = 'r.a.v.d.doel@student.tue.nl',
    license = 'MIT',
    description = 'A command line tool that provides simple penetration testing capabilities.',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = 'https://github.com/Raphaelvddoel/2IC80',
    py_modules = ['cuckoo_byte', 'functions'],
    packages = find_packages(),
    python_requires='>=3.10',
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    entry_points = '''
        [console_scripts]
        cuckoo=cuckoo_byte:cli
    '''
)