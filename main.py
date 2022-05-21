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

def elaborate_response(url_under_test, parameter_under_test, parameter_under_test_value, response):
    url_under_test = url_under_test[1:] # remove initial slash

    if DEBUG:
        print(f'\n[DEBUG] - URL: {url_under_test}')
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
        print(f'Found a command injection for URL: {url_under_test}, parameter: {parameter_under_test}, payload: {parameter_under_test_value}')
        write_vulnerabilty_report(f'\n{datetime.now()} - Found a command injection for URL: {url_under_test}, parameter: {parameter_under_test}, payload: {parameter_under_test_value}')

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
def read_payloads(requestsDict):
    with open(PAYLOADS_INPUT_PATH) as f:
        i = 0

        for line in f:
            payloads = line.strip().split(PAYLOADS_SPLIT_VAL)
            requestsDict[i]['payloads'] = payloads
            i += 1

def send_request(requestsDict):
    for request in requestsDict:
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
                    elaborate_response(request['url'], request['parameters'][i], payload, requests.get(final_url, params=data))
                elif 'POST' == request['method'].upper():
                    elaborate_response(request['url'], request['parameters'][i], payload, requests.post(final_url, data=data))
                else:
                    print(f'Method {request["method"]} is not supported')        

def main():
    requestsDict = [ ]

    read_requests_details(requestsDict)
    read_payloads(requestsDict)

    if DEBUG:
        print('[DEBUG] - REQUESTS DICTIONARY')
        print(requestsDict)

    send_request(requestsDict)

if __name__ == '__main__':
    main()