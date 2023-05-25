# 2IC80 group X 22/23 TU/e

## Setup

### Virtual environment
1. Create a venv <br>
`python -m venv venv`
2. Activate your venv <br>
    a. Windows <br>
    `.\venv\scripts\activate` <br>
    b. Mac os / unix <br>
    `source venv/bin/activate`

To deactivate when you are done, just exit or run<br>
`deactivate`

Install requirements <br>
`pip install -r requirements.txt`

Package cli tool <br>
`python setup.py develop`

After packaging the tool you can use `cuckoo` commands