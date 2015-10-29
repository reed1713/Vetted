# vetted api client for yara_binary rules
# author reed3276@gmail.com

import requests
import json
import subprocess
import signal
import os
import datetime
import time
import sys
import re
import config

# log time
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

# change into dir, so cron will log correctly.
os.chdir(config.PATH_TO_YARA_BINMEM_DIR)

def download_vetted_memsigs_json():

	mem_apipath = '/api/vetted/memory_yara/json/'

	url = config.VETTED_SERVER + mem_apipath
	payload = {'api_key' : config.API_KEY}
	r = requests.get(url, params=payload)

	if r.status_code == 200:
	    out = r.json()
	    return out
	else:
	    with open('yara_binary_memory_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + config.VETTED_SERVER + " check api key or server address" + "\n")

def parse_yara_memsigs_sigs():

	'''
	parse and output list of newline separated yara rules
	'''

	out = download_vetted_memsigs_json()

	if out != None:
		regex = re.compile('\r\n}$')
		writelist = []
		for o in out['vetted']:
			for sig in o['indicators']:
				out = regex.sub('\r\n}\r\n\r\n', sig)
				writelist.append(out)
		return writelist
	else:
		with open('yara_binary_memory_client.log', 'a') as logfile:
			logfile.write(st + ": no binary yara signatures to download from the vetted server" + "\n")

def write_memsigs_to_file():

	out = parse_yara_memsigs_sigs()

	with open(config.PATH_TO_YARA_MEM_RULES, 'w+') as f:
		f.write("/*\r\n Vetted yara_memory rules \r\n*/\r\n\r\n")
		f.write(config.IMPORT_PE + "\r\n")
		f.write(config.IMPORT_ELF + "\r\n")
		f.write(config.IMPORT_CUCKOO + "\r\n\r\n")
		f.writelines(out)

def download_vetted_binsigs_json():

	bin_apipath = '/api/vetted/binary_yara/json/'

	url = config.VETTED_SERVER + bin_apipath
	payload = {'api_key' : config.API_KEY}
	r = requests.get(url, params=payload)

	if r.status_code == 200:
	    out = r.json()
	    return out
	else:
	    with open('yara_binary_memory_client.log', 'a') as logfile:
	    	logfile.write(st + ": failed to connect to " + config.VETTED_SERVER + " check api key or server address" + "\n")

def parse_yara_binsigs_sigs():

	'''
	parse and output list of newline separated yara rules
	'''

	out = download_vetted_binsigs_json()

	if out != None:
		regex = re.compile('\r\n}$')
		writelist = []
		for o in out['vetted']:
			for sig in o['indicators']:
				out = regex.sub('\r\n}\r\n\r\n', sig)
				writelist.append(out)
		return writelist
	else:
		with open('yara_binary_memory_client.log', 'a') as logfile:
			logfile.write(st + ": no binary yara signatures to download from the vetted server" + "\n")	

def write_binsigs_to_file():

	out = parse_yara_binsigs_sigs()

	with open(config.PATH_TO_YARA_BIN_RULES, 'w+') as f:
		f.write("/*\r\n Vetted yara_binary rules \r\n*/\r\n\r\n")
		f.write(config.IMPORT_PE + "\r\n")
		f.write(config.IMPORT_ELF + "\r\n")
		f.write(config.IMPORT_CUCKOO + "\r\n\r\n")
		f.writelines(out)

def kill_cuckoo_process():

	p = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()

	for line in out.splitlines():
		if "cuckoo.py" in line:
			pid = int(line.split()[1])
			os.kill(pid, signal.SIGKILL)

def main():

	'''
	restart cuckoo, check for fail
	continuously writes cuckoo.py output to yara_binary_memory_client.log file
	'''

	write_binsigs_to_file()
	write_memsigs_to_file()
	kill_cuckoo_process()

	if os.path.isfile(config.PATH_TO_CUCKOO):
		with open('yara_binary_memory_client.log', 'a') as logfile:
	 		logfile.write(st + ": successfully loaded yara binary/memory rules" + "\n")
	 		# remove 'python' from this line if you've made cuckoo.py executable
	 	proc = subprocess.Popen(['python', config.PATH_TO_CUCKOO], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	 	for line in iter(proc.stderr.readline, b''):
	 		 with open('yara_binary_memory_client.log', 'a') as logfile:
	 		 	logfile.write(line.rstrip() + '\n')
	else:
		with open('yara_binary_memory_client.log', 'a') as logfile:
			logfile.write(st + ": cuckoo.py not found in specified path" + "\n")

if __name__ == '__main__':
	main()