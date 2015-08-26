# vetted api client for bro intel
# author reed3276@gmail.com

#local.bro example
#load vetted intel
#@load /opt/Vetted/clients/Vetted_Bro_Client

import requests
import json
from collections import defaultdict
import subprocess
import os.path
import datetime, time
from sys import exit

# vars are for testing, replace with your own
VETTED_SERVER = 'http://192.168.7.112:5000'
API_KEY = '8e662aee78554f579a24af53ad9b1856'
PATH_TO_BROCTL = '/opt/bro/bin/broctl'

# log time vars
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def download_vetted_json():

	url = VETTED_SERVER + '/api/vetted/network_bro_intel/json/'
	payload = {'api_key' : API_KEY}
	r = requests.get(url, params=payload)

	if r.status_code == 200:
	    out = r.json()
	    return out
	else:
	    with open('vetted_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + VETTED_SERVER + " check api key or server address" + "\n")

def dedupe_indicators():

	vettedintel = download_vetted_json()
	test = vettedintel.itervalues().next()
	vettedlist = []
	dd = defaultdict(list)

	for t in test:
		for i in t['indicators']:
			ind_type = ''.join(i.keys())
			ind = ''.join(i.values())
			newdict = {(ind, ind_type) : (t['source'], t['tags'])}
			for key, value in newdict.iteritems():
				dd[key].append(value)				
	return dd

def prepare_for_file():

	'''
	takes the dedupe list and cleans for file write
	'''

	dirty_d = dedupe_indicators()
	success = []

	for d in dirty_d.items():
		indicator = d[0][0]
		indicator_type =  d[0][1]
		listofsources = []
		listoftags = []
		for test in d[1]:
			listofsources.append(test[0])
			listoftags.append(test[1])
		final = (indicator, indicator_type, listofsources, listoftags)
		success.append(final)
	return success

def write_to_file():

	'''
	if not a supported bro intel type, its disregarded and writes to log.
	then writes vetted intel to file. removes unicode and dedupes.
	'''
	
	cleanlist = prepare_for_file()
	supported_types = ['DOMAIN', 'ADDR', 'URL', 'FILE_NAME', 'CERT_HASH', 'EMAIL', 'FILE_HASH']

	with open('vetted_intel.dat', 'w') as intelfile:	
		intelfile.write('#fields	indicator	indicator_type	meta.source' + '\n')
		for c in cleanlist:
			if c[1] not in supported_types:
				with open('vetted_client.log', 'a') as logfile:
					logfile.write(st + ": unsupported intel type: " + c[1] + '\n')
			else:
				sources = str([str(x) for x in c[2]]).replace(',','')
				combinetags = set(str(r) for v in c[3] for r in v)
				tags = str([str(x) for x in combinetags]).replace(',','')
				indicator_type = c[1]
				indicator = c[0]
				intelfile.write(indicator + '\t' + 'Intel::'+ indicator_type + '\t' + 'vetted-' + tags + '-' + sources + '\n')

def main():

	write_to_file()

	if os.path.isfile(PATH_TO_BROCTL):
		FNULL = open(os.devnull, 'w')
		subprocess.call([PATH_TO_BROCTL, 'restart'], stdout=FNULL, stderr=subprocess.STDOUT)
		with open('vetted_client.log', 'a') as logfile:
			logfile.write(st + ": successfully downloaded bro intel" + "\n")
	else:
		with open('vetted_client.log', 'a') as logfile:
			logfile.write(st + ": BRO RESTART FAILED: broctl bin not found in specified path" + "\n")

if __name__ == '__main__':

	if not os.geteuid() == 0:
		with open('vetted_client.log', 'a') as logfile:
			logfile.write(st + ": Needs to be run as root" + "\n")
			exit()
   	else:
		main()
