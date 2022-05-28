# Scanner and Command Injection
## Introduction
The idea of this vulnerability scanner and command injection is to show some examples on how vulnerable parameters can be exploited in order to execute commands.

## Note
The scanner won't work on every environment, commands and arguments injections are based on linux commands.

## Requirements
### Languages
+ Python (for application code)
+ PHP (for vulnerable server code)

### Libraries
+ requests
+ click

## Code explanation
The application code reads input files (created by the user) and send HTTP requests based on the specified method. Commands in payloads file will be injected into each parameter by using permutations. A different request will be sent for each payloads permutation.<br>
Server response is elaborated in order to check vulnerabilities. This check is based on a simple idea of looking if specific strings are in response body.<br>
If a vulnerability is found a descriptive line will be written inside the output file.
There are two modes to run the code:
+ cmd: used to test commands and arguments injections
+ sql: used to test sql injections. In this mode payloads are used in a differt way than cmd mode. This mode is based on a specific command (in config file) used to perform a Union-based SQL injection. Other injections can be tested but no check is performed for them.

## Input files
+ assets/input/requests-details.txt<br>
used to specify the list of requests details containing HTTP method, resource and parameters under test.<br>
The format used to specify the details is: HTTP method:resource:parameter1,parameter2,..
+ assets/input/payloads.txt<br>
used to specify the list of commands that will be used in a specific request (based on files row number). <br>
Each command is separated by tilde.

### requests.details.txt example (cmd mode)
```
GET:/ping.php:host
GET:/ping-escapeshellcmd.php:host
GET:/find-escapeshellcmd.php:input
GET:/ping-no-amp.php:host
```

### requests.details.txt example (sql mode)
```
GET:/find.php:search
POST:/login.php:user,pass
POST:/login2.php:user,pass
GET:/search_by_price2.php:max
```

### payloads.txt example (cmd mode)
```
;cat /etc/passwd
;ls -la
ping.php -exec whoami ;
;head ping.php
```

### payloads.txt example (sql mode)
```
--noc
--noc
--noc
--noc
```

## Config file example
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

COMMAND_COLUMNS_NUMBER = '--noc' # command to find the number of columns in a table
```

## Database setup
The data stored in the database will be used to test sql injections.<br>
Execute files in sqli-target/setup to create and populate the database.

## Server execution
### For commands and arguments injections
```console
foo@bar:~$ cd "target environment"
foo@bar:~$ php -S localhost:8000
```

### For sql injections
```console
foo@bar:~$ cd sqli-target
foo@bar:~$ php -S localhost:8000
```

## Application execution
### Arguments
+ -m, Injection mode, required. Permitted values [cmd, sql]

### For cmd mode
```console
foo@bar:~$ python main.py -m cmd
```

### For sql mode
```console
foo@bar:~$ python main.py -m sql
```

## Output
Output file is saved on assets/output/vulnerability-output.txt file.

## Author
+ [Andrea Mercuri](https://github.com/ilmercu)