DEBUG = True

TARGET = 'http://localhost:8000'

VULNERABILITY_OUTPUT_PATH = 'assets/output/vulnerability-output.txt'

REQUESTS_SPLIT_VAL = ':'
REQUESTS_PARAMETERS_SPLIT_VAL = ','
PAYLOADS_SPLIT_VAL = '~'

CURRENT_USER = 'andre' # known user used for whoami test

# special commands
COMMAND_COLUMNS_NUMBER = '--noc' # command to find the number of columns in a table. Valid only in sql mode