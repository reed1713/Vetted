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
		pass
	else:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + config.VETTED_SERVER + " check api key or server address" + "\n")

def json_to_listofdicts():

	'''
	parse out rule, if rule doesnt have sid then assign sid. 
	POST updated rule back to vetted server. 
	write latest sid to config. 
	write rules to local.rules file.
	return list of dictionaries.
	'''

	out = download_vetted_json()
	dd = defaultdict(list)
	writesigs = []
	networklist = []

	if out == None:
	    with open('vetted_snort_client.log', 'a') as logfile:
	    	logfile.write(st + ": no signatures to download." + "\n")
	else:
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

					# prep and send sigs to Vetted server
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

					# write sigs to local.rules file
					with open(config.PATH_TO_RULES_FILE, 'r+') as f:
						if type(parsed_rule) == 'rule.Rule':
							ruletype = unicode(parsed_rule.raw)
						else:
							ruletype = parsed_rule.raw
						rulelist = str(ruletype)
						writesigs.append(rulelist)
						final = '\r\n\r\n'.join(writesigs)
						f.write(final)
						f.truncate()

					# writes next sid to config file
					with open('config.py', 'r+') as f:
						text = f.read()
						out = re.sub('SID_START = .*', 'SID_START = ' + str(config.SID_START), text)
						f.seek(0)
						f.write(out)

	# create dictionary with all the data needed for sid-msg.map file and return it
					networkdumps = json.dumps(parsed_rule)
					networkloads = json.loads(networkdumps)
					networkloads['sid'] = parsed_rule.sid
					networkloads['tags'] = o['tags']
					networkloads['source'] = o['source']
					networkloads['priority'] = o['priority']
					networklist.append(networkloads)
	return networklist
		
def overwrite_sidmap_entries():

	'''
	find the vetted entries in the sid-msg.map file and overwrite them with the newly downloaded entries.
	'''

	out = json_to_listofdicts()
	list_of_sigmsgs = []

	for o in out:
		sidmsgs = str(o['sid']) + ' || ' + o['msg'] + ' || ' + 'source, ' + o['source'] + ' || ' + 'tags, ' + str([str(x) for x in o['tags']]).replace(',','').replace('[','').replace(']','')
		list_of_sigmsgs.append(sidmsgs)
	cleansidmsgs = '\r\n'.join(list_of_sigmsgs)
	filename = config.PATH_TO_SID_MAP_FILE
	writesidsmsgs = '### Vetted ###\r\n' + cleansidmsgs + '\r\n### Vetted_end ###'

	with open(filename, 'r+') as f:
		text = f.read()
		test = re.search('### Vetted ###', text)
		if test != None:
			text = re.sub('### Vetted ###.*### Vetted_end ###', writesidsmsgs, text, flags=re.DOTALL)
			f.seek(0)
			f.write(text)
			f.truncate()
		else:
			f.write(writesidsmsgs)

def main():

	'''
	check if rule-update fails
	'''

	overwrite_sidmap_entries()

	if os.path.isfile(config.PATH_TO_RULE_UPDATE):
		proc = subprocess.Popen([config.PATH_TO_RULE_UPDATE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = proc.communicate()
		stdout = stdout.split("\n")
		for line in stdout:
			test = re.search('.* FAIL .*', line)
			if test != None:
				with open('vetted_snort_client.log', 'a') as logfile:
					logfile.write(st + ": rule-update failed during restart process - check /var/log/nsm/<SENSOR_NAME>/snortu-1.log file for more info" + "\n")
					sys.exit()
		with open('vetted_snort_client.log', 'a') as logfile:
			logfile.write(st + ": successfully loaded snort rules" + "\n")
	else:
		with open('vetted_snort_client.log', 'a') as logfile:
			logfile.write(st + ": rule-update bin not found in specified path" + "\n")

if __name__ == '__main__':
	main()