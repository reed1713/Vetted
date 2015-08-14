# Vetted_Bro_Client

### Overview

Uses the vetted api to download, dedupe and format indicators for bro intel framework consumption.

### Format

indicator, type, vetted, tags, intel source(s), notice framework flag

### Install

change the dir path in the vetted_intel.bro file to point to your vetted_intel.dat file. change the global vars in the api script to match your environment. add line '@load /path/to/your/Vetted_Bro_Client' in your local.bro file. run ./broctl install. run vetted_api_client.py. 

### Example

```
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url	meta.do_notice
badguyexe.exe	Intel::FILE_NAME	vetted	['tibet', 'cve-2012-0158', 'cve-2014-4114', 'government', 'poison ivy', 'plugx', 'dynamic-dns', 'targeted threats', 'cve-2010-3333', 'targeted attack', 'hong kong', 'russia']	['citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']	F
badguydomain.net	Intel::DOMAIN	vetted	['tibet', 'financial', 'government', 'cve-2012-0158', 'cryptowall', 'spearphishing', 'grabit', 'poison ivy', 'cve-2014-4114', 'plugx', 'dynamic-dns', 'targeted threats', 'china', 'cve-2010-3333', 'hong kong', 'taiwan', 'targeted attack', 'cve-2014-0497', 'russia', 'espionage']	['securelist.com/blog/research/71713/darkhotels-attacks-in-2015/', 'citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']	F
192.168.1.1	Intel::ADDR	vetted	['tibet', 'financial', 'government', 'cve-2012-0158', 'cryptowall', 'spearphishing', 'grabit', 'poison ivy', 'cve-2014-4114', 'plugx', 'dynamic-dns', 'targeted threats', 'china', 'cve-2010-3333', 'hong kong', 'taiwan', 'targeted attack', 'cve-2014-0497', 'russia', 'espionage']	['securelist.com/blog/research/71713/darkhotels-attacks-in-2015/', 'citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']	F
```