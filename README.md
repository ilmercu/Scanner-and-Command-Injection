# Scanner and Command Injection
## Introduction
The idea of this vulnerability scanner and command injection is to show some examples on how vulnerable parameters can be exploited in order to execute commands.

## Note
The scanner won't work on every environment, injections are based on linux commands.

## Requirements
+ Python (for application code)
+ PHP (for vulnerable server code)

## Input files
+ assets/input/requests-details.txt<br>
used to specify request details containing HTTP method, resource and parameters under test.<br>
The format used to specify the details is: HTTP method:resource:parameter1,parameter2,..
+ assets/input/payloads.txt<br>
used to specify the commands that will be used in a specific request (based on files row number). <br>
The format used to specify commands is: command1~command2~..

## Config file
```python
DEBUG = True # if True, code execution prints debugging lines

TARGET = 'http://localhost:8000' # target

VULNERABILITY_OUTPUT_PATH = 'assets/output/vulnerability-output.txt' # output path

REQUESTS_INPUT_PATH = 'assets/input/requests-details.txt' # requests list path
PAYLOADS_INPUT_PATH = 'assets/input/payloads.txt' # commands list path

REQUESTS_SPLIT_VAL = ':' # split char for requests
REQUESTS_PARAMETERS_SPLIT_VAL = ',' # split char for parameters in requests
PAYLOADS_SPLIT_VAL = '~' # split char for commands values

CURRENT_USER = 'andre' # known user used for whoami test
```

## Code explanation
The application code reads input files and send HTTP requests based on the specified method. Each command in payloads file will be injected into each parameter separately, which means that only one parameter at time will contain a command, the others will contain a valid value. For each combiantion of (parameter, value) a different request will be sent.<br>
Server response is elaborated in order to check vulnerabilities. This check is based on a simple idea of looking if specific strings are in response body.<br>
If a vulnerability is found a descriptive line will be written inside the output file. 

## Run execution
### Server
```console
foo@bar:~$ cd "target environment"
foo@bar:~$ php -S localhost:8000
```

### Application
```console
foo@bar:~$ python main.py
```

## Output
Output file is saved on assets/output/vulnerability-output.txt file.

## Author
+ [Andrea Mercuri](https://github.com/ilmercu)