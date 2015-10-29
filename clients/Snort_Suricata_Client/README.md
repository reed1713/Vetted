# Snort_Suricata_Client

### Overview

Uses the vetted api to download and format snort and suricata signatures. assigns new sid if it doesnt exist, and POSTs updated rule back to the vetted server. also, updates sid-msg.map file and adds source and tags for additional rule context.

### Install

Edit the config.py to match your environment. run: sudo python snort_suricata_client.py. Meant to be run as a cronjob, to continually pull down and update your signatures.