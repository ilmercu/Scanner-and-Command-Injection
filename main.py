from config import *
import requests
import os
from datetime import datetime

def write_vulnerabilty_report(message):
    directories, filename = os.path.split(VULNERABILITY_OUTPUT_PATH)

    if not os.path.exists(directories):
        os.makedirs(directories)

    with open(VULNERABILITY_OUTPUT_PATH, 'a+') as f:
        f.write(message)

def elaborate_response(http_method, url_under_test, parameter_under_test, parameter_under_test_value, response):
    url_under_test = url_under_test[1:] # remove initial slash

    if DEBUG:
        print(f'\n[DEBUG] - URL: {url_under_test}')
        print(f'\n[DEBUG] - HTTP METHOD: {http_method}')
        print(f'[DEBUG] - COMPLETE URL: {response.url}')
        print(f'[DEBUG] - PARAMETER UNDER TEST: {parameter_under_test}')
        print(f'[DEBUG] - PARAMETER UNDER TEST VALUE: {parameter_under_test_value}')
        
        print('[DEBUG] - RESPONSE')
        print(response.text)

    vulnerable = False

    # check expected results
    if 'ls' in parameter_under_test_value:
        if url_under_test in response.text:
            vulnerable = True
    elif 'cat /etc/passwd' in parameter_under_test_value:
        if 'root' in response.text:
            vulnerable = True
    elif ('head' in parameter_under_test_value or 'grep php' in parameter_under_test_value) and '.php' in parameter_under_test_value:
        if '<?php' in response.text:
            vulnerable = True
    elif 'whoami' in parameter_under_test_value:
        if CURRENT_USER in response.text:
            vulnerable = True
    elif 'ifconfig | grep inet' in parameter_under_test_value:
        if 'inet' in response.text:
            vulnerable = True

    if vulnerable:
        print(f'Found a command injection for URL: {url_under_test}, HTTP method: {http_method}, parameter: {parameter_under_test}, payload: {parameter_under_test_value}')
        write_vulnerabilty_report(f'\n{datetime.now()} - Found a command injection for URL: {url_under_test}, HTTP method: {http_method}, parameter: {parameter_under_test}, payload: {parameter_under_test_value}')

# read requests details
def read_requests_details(requestsDict):
    with open(REQUESTS_INPUT_PATH) as f:
        for line in f:
            values = line.strip().split(REQUESTS_SPLIT_VAL)

            requestsDict.append({ 
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
            requests_dict[i]['payloads'] = payloads
            i += 1

        if i != len(requests_dict):
            raise IndexError()

def send_request(requests_dict):
    for request in requests_dict:
        final_url = TARGET + request['url']
        
        for payload in request['payloads']:
            data = { }
            
            # test all payloads combinations
            for i in range(0, len(request['parameters'])):
                for j in range(0, len(request['parameters'])):
                    if j == i:
                        data[request['parameters'][i]] = payload
                    else:
                        data[request['parameters'][j]] = 'valid_string' # valid value for input type
            
                if 'GET' == request['method'].upper():
                    elaborate_response(request['method'], request['url'], request['parameters'][i], payload, requests.get(final_url, params=data))
                elif 'POST' == request['method'].upper():
                    elaborate_response(request['method'], request['url'], request['parameters'][i], payload, requests.post(final_url, data=data))
                else:
                    print(f'Method {request["method"]} is not supported')        

def main():
    requests_dict = [ ]

    read_requests_details(requests_dict)

    try:
        read_payloads(requests_dict)
    except IndexError:
        print('Error: mismatching rows number between requests-details and payloads files')
        exit()
    
    if DEBUG:
        print('[DEBUG] - REQUESTS DICTIONARY')
        print(requests_dict)

    send_request(requests_dict)

if __name__ == '__main__':
    main()