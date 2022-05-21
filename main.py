from config import *
import requests

requestsDict = [ ]

# read requests details
with open(REQUESTS_INPUT_PATH) as f:
    for line in f:
        values = line.strip().split(REQUESTS_SPLIT_VAL)

        requestsDict.append({ 
            'method':  values[0],
            'url': values[1],
            'parameters': values[2].split(REQUESTS_PARAMETERS_SPLIT_VAL),
        })

# read payloads to inject
with open(PAYLOADS_INPUT_PATH) as f:
    i = 0

    for line in f:
        payloads = line.strip().split(PAYLOADS_SPLIT_VAL)
        
        requestsDict[i]['payloads'] = payloads

        i += 1

if DEBUG:
    print('[DEBUG] - REQUESTS DICTIONARY')
    print(requestsDict)

for request in requestsDict:
    final_url = TARGET + request['url'] + '?'
    
    for payload in request['payloads']:
        payload_injection = ''

        for parameter in request['parameters']:
            payload_injection += parameter + '=' + payload
        
        if DEBUG:
            print('\n[DEBUG] - URL')
            print(f'{final_url}{payload_injection}')
        
        r = requests.get(final_url + payload_injection)

        if DEBUG:
            print('[DEBUG] - REQUEST RESULT')
            print(f'{r.text}')