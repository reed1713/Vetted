# vetted api client for snort rules
# author reed3276@gmail.com

import requests
import json
from collections import defaultdict
import subprocess
import os.path
import datetime, time
from sys import exit
import rule

# vars are for testing, replace with your own
VETTED_SERVER = 'http://192.168.7.115:5000'
API_KEY = '8e662aee78554f579a24af53ad9b1856'
PATH_TO_RULES_FILE = '/etc/nsm/rules/local.rules'
PATH_TO_SID_MAP_FILE = '/etc/nsm/rules/sid-msg.map'
RULE_RESTART = 'rule-update'
SID_START = 50000000

# log time vars
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def download_vetted_json():

	url = VETTED_SERVER + '/api/vetted/network_snort/json/'
	payload = {'api_key' : API_KEY}
	r = requests.get(url, params=payload)

	if r.status_code == 200:
	    out = r.json()
	    return out
	else:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + VETTED_SERVER + " check api key or server address" + "\n")

def post_vetted_sig(hash_type):

	url = VETTED_SERVER + '/api/vetted/network_snort/json/' + hash_type
	payload = {'api_key' : API_KEY }

	indicators = {
	"indicators": ["alert tcp any any -> $HOME_NET 7789 (msg: \"test\"; reference: url,http://holisticinfosec.blogspot.com/2011/12/choose-2011-toolsmith-tool-of-year.html; content: \"toolsmith\"; flow:to_server; nocase; rev:1;)"
      ]
    }
	r = requests.post(url, params=payload, data=json.dumps(indicators))
	if r.status_code == 200:
		with open('vetted_snort_client.log', 'a') as logfile:
			logfile.write(st + ": successfully POSTed signatures to the vetted server" + "\n")
			return 'SUCCESS'
	else:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + VETTED_SERVER + " check api key or server address" + "\n")
	    	return 'FAIL'

def json_to_listofdicts():

	out = download_vetted_json()
	networklist = []
	if out == None:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": No signatures to download." + "\n")
	else:
		for o in out['vetted']:
			sig = o['indicators']
			for s in sig:
				s.replace('\r\n','')
				parsed_rule = rule.parse(s)
				networkdumps = json.dumps(parsed_rule)
				networkloads = json.loads(networkdumps)
				networkloads['tags'] = o['tags']
				networkloads['source'] = o['source']
				networkloads['priority'] = o['priority']
				networklist.append(networkloads)
	return networklist
		
def sid_rulename_source_tags_dict():
	'''
	create a list of dicts [{sid : rulename string, source string, tags list},]
	this will be used to write to the sid-msg.map file
	'''
	pass
def check_for_sid():
	'''
	check if signature has sid, if not assign sid and log import
	'''
	pass
def overwrite_sidmap_entries():
	'''
	find the vetted entries in the sid-msg.map file and overwrite them with the newly
	downloaded entries. if ### Vetted ### not in sid file, create start and end markers.
	'''
	pass
def get_most_recent_sid():
	'''
	locates the most recent sid to increment correctly
	'''
	pass

if __name__ == '__main__':
	#out = post_vetted_sig('5f24504ae2defc0de1caa8d1301b1667')
	out = json_to_listofdicts()
	print out