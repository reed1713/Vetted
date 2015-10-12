# vetted api client for snort rules
# author reed3276@gmail.com

import requests
import json
import subprocess
import os
import datetime
import time
import sys
import rule
import re
import config
from collections import defaultdict

# log time
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

# change into dir, so cron will log correctly.
os.chdir(config.PATH_TO_DIR)

def download_vetted_json():

	url = config.VETTED_SERVER + '/api/vetted/network_snort/json/'
	payload = {'api_key' : config.API_KEY}
	r = requests.get(url, params=payload)

	if r.status_code == 200:
	    out = r.json()
	    return out
	else:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + config.VETTED_SERVER + " check api key or server address" + "\n")

def post_vetted_sig(hash_type, indic):

	url = config.VETTED_SERVER + '/api/vetted/network_snort/json/' + hash_type
	payload = {'api_key' : config.API_KEY }


	indicators = {
	"indicators": indic
    }
	r = requests.post(url, params=payload, data=json.dumps(indicators))
	if r.status_code == 200:
		with open('vetted_snort_client.log', 'a') as logfile:
			logfile.write(st + ": successfully POSTed signatures to the vetted server" + "\n")
			return 'SUCCESS'
	else:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + config.VETTED_SERVER + " check api key or server address" + "\n")
	    	return 'FAIL'

def json_to_listofdicts():

	'''
	parse out rule, if rule doesnt have sid then assign sid. POST updated rule back to 
	vetted server. write latest sid to config. return dict of rules.
	'''

	out = download_vetted_json()
	writesigs = []
	dd = defaultdict(list)
	if out == None:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": no signatures to download." + "\n")
	else:
		listit = []
		for o in out['vetted']:
			sig = o['indicators']
			for s in sig:
				parsed_rule = rule.parse(s)
				if parsed_rule != None:
					if parsed_rule.sid == None:
						parsed_rule.sid = str(config.SID_START)
						rule_with_sid = rule.parse(parsed_rule.raw[:-1] + ' sid: ' + parsed_rule.sid + ';)')
						with open('vetted_snort_client.log', 'a') as logfile:
							logfile.write(st + ": assigned sid " + str(config.SID_START) + ' to rule \"' + parsed_rule.msg + '\"' + "\n")
						config.SID_START = int(config.SID_START) + 1
						parsed_rule.raw = rule_with_sid
					else:
						pass

					rulesiddict = {o['type_hash'] : str(parsed_rule.raw)}
					for key, value in rulesiddict.iteritems():
						dd[key].append(value)
					for d in dd.iteritems():
						hash_type = d[0]
						addnewline = [x.replace(';)', ';)\r\n\r\n') for x in d[1][:-1]]
						final = addnewline + d[1][-1:]
						out = json.dumps(final)
						indict = json.loads(out)
						post_vetted_sig(hash_type, indict)

					with open(config.PATH_TO_RULES_FILE, 'r+') as f:
						print parsed_rule.raw
						print type(parsed_rule.raw)
						#writesigs.append(parsed_rule.raw)
						#final = '\r\n'.join(writesigs)
						#f.write(final)

					# writes next sid to config file
					with open('config.py', 'r+') as f:
						text = f.read()
						out = re.sub('SID_START = .*', 'SID_START = ' + str(config.SID_START), text)
						f.seek(0)
						f.write(out)


	#return the dict of values for sid msg file parsing
	# 	print parsed_rule
	# 	networkdumps = json.dumps(parsed_rule)
	# 	networkloads = json.loads(networkdumps)
	# 	networkloads['tags'] = o['tags']
	# 	networkloads['source'] = o['source']
	# 	networkloads['priority'] = o['priority']
	# 	networklist.append(networkloads)
	# print networklist
		
def sid_rulename_source_tags_dict():
	'''
	create a list of dicts [{sid : rulename string, source string, tags list},]
	this will be used to write to the sid-msg.map file
	'''
	pass
def overwrite_sidmap_entries():
	'''
	find the vetted entries in the sid-msg.map file and overwrite them with the newly
	downloaded entries.
	'''
	filename = 'testsid.map'
	bar = '### Vetted ###\r\n5000000 || test || source,googleprojectzero.blogspot.com/2015/08/windows-10hh-symbolic-link-mitigations.html || tags, test test1 test3\r\n5000001 || blah || source,googleprojectzero.blogspot.com/2015/08/windows-10hh-symbolic-link-mitigations.html || tags, test test1 test3\r\n### Vetted_end ###'

	with open(filename, 'r+') as f:
		text = f.read()
		test = re.search('### Vetted ###', text)
		if test != None:
			text = re.sub('### Vetted ###.*### Vetted_end ###', bar, text, flags=re.DOTALL)
			f.seek(0)
			f.write(text)
			f.truncate()
			with open('vetted_snort_client.log', 'a') as logfile:
				logfile.write(st + ": successfully overwrote entries in the sid-msg.map file" + "\n")
		else:
			f.write(bar)
			with open('vetted_snort_client.log', 'a') as logfile:
				logfile.write(st + ": successfully wrote entries to the sid-msg.map file" + "\n")

if __name__ == '__main__':
	#out = post_vetted_sig('5f24504ae2defc0de1caa8d1301b1667')
	out = json_to_listofdicts()
	#print out
	#overwrite_sidmap_entries()