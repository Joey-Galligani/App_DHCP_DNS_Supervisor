import requests
import time
import os

API_SERV = os.getenv('API_SERV')
TIMEOUT = os.getenv('TIMEOUT')

def count_addr(count):
    stats = requests.get(API_SERV+'/stats/dhcp')
    stats = stats.json()
    used = stats['used'] + count

    headers = {'Content-Type': 'application/json'}

    request = requests.post(API_SERV+'/stats/dhcp/used',json={'used':used},headers=headers)

    print("[+] Pool " + str(count))

def alerts(frame, allowed):
    if ((frame['dhcp']['op'] == 5) and not (frame['ipsrc'] in allowed)):

        headers = {'Content-Type': 'application/json'}

        request= requests.post(API_SERV+'/alerts/dhcp',
                               json={'type':'DHCP Rogue',
                                     'description':"L'adresse "+frame['ipsrc']+
                                     " se fait passer pour un serveur DHCP auprès de la machine "+
                                     frame['ipdst'],"frame":frame['ID']},
                               headers=headers)

        print("[!] Alerts")
    else:
        pass


seconds = TIMEOUT
while True :
    # Request to the API
    response = requests.get(API_SERV+'/analyse/dhcp')

    # Check if timeout is exceeded to renew chache data
    if seconds == TIMEOUT:
        resp = requests.get(API_SERV+'/analyse/dhcp/allowed')

        if resp.status_code == 200:
            allowed = resp.json()
        else:
            allowed = []

        seconds = 0

    if response.status_code == 200:

        data = response.json()

        # If returned data is the correct type
        if type(data) == dict:

            print("[.] Analyzing")

            if data['dhcp']['op']==5:
                count_addr(+1)
            elif data['dhcp']['op']==7:
                count_addr(-1)

            # If we have a list of allowed dhcp we compare to it
            if len(allowed) > 0:
                alerts(data, allowed)
        else:
            # If last replie was empty we wait 1 second to send another request
            time.sleep(1)

    seconds += 1
