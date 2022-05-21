from config import *
import requests

def elaborate_response(response):
    if DEBUG:
        print('\n[DEBUG] - URL')
        print(f'{response.url}')
        
        print('[DEBUG] - REQUEST RESULT')
        print(f'{response.text}')

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

            for parameter in request['parameters']:
                data[parameter] = payload
            
            if 'GET' == request['method'].upper():
                elaborate_response(requests.get(final_url, params=data))
            elif 'POST' == request['method'].upper():
                elaborate_response(requests.post(final_url, data=data))
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

if __name__=="__main__":
    main()