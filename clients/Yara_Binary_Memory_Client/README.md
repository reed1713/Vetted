# Yara_Binary_Memory_Client

### Overview

Downloads binary and memory yara signatures using the vetted server api. Parses and puts them in the appropriate cuckoo yara dir. 

### Install

Edit the config.py to match your environment. run: sudo python yara_binary_memory_client.py. Meant to be run as a cronjob, to continually pull down and update your signatures.