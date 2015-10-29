# Bro_Intel_Client

### Overview

Uses the vetted api to download, dedupe and format indicators for bro intel framework consumption.

### Format

indicator, type, vetted-[tags]-[intel source(s)]

### Install

change the dir path in the vetted_intel.bro file to point to your vetted_intel.dat file. change the global vars in the api script to match your environment. add line '@load /path/to/your/Vetted_Bro_Client' in your local.bro file. run ./broctl install. run: sudo vetted_api_client.py. Meant to be run as a cronjob, to continually pull down and update your indicators.

### Example

```
#fields	indicator	indicator_type	meta.source
badguyexe.exe	Intel::FILE_NAME	vetted-['tibet' 'cve-2012-0158' 'cve-2014-4114' 'government']-['citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']
badguydomain.net	Intel::DOMAIN	vetted-['tibet' 'financial' 'government' 'cve-2012-0158' 'cryptowall' 'spearphishing' 'grabit' 'poison ivy' 'cve-2014-4114' 'plugx' 'dynamic-dns' 'targeted threats' 'china' 'cve-2010-3333' 'hong kong' 'taiwan' 'targeted attack' 'cve-2014-0497' 'russia' 'espionage']-['securelist.com/blog/research/71713/darkhotels-attacks-in-2015/' 'citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']
192.168.1.1	Intel::ADDR	vetted-['tibet' 'financial' 'government' 'cve-2012-0158' 'cryptowall' 'spearphishing' 'grabit' 'poison ivy' 'cve-2014-4114' 'plugx' 'dynamic-dns' 'targeted threats' 'china' 'cve-2010-3333' 'hong kong' 'taiwan' 'targeted attack' 'cve-2014-0497' 'russia' 'espionage']-['securelist.com/blog/research/71713/darkhotels-attacks-in-2015/' 'citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']
```

### Example Output

```
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       seen.indicator  seen.indicator_type        seen.where      sources
#types  time    string  addr    port    addr    port    string  string  string  string  enum    enum    set[string]
1440601830.343640       CSx0AW1m5CMC76lXng      192.168.7.112   9283    192.168.7.1     53      -       -       -       badguydomain.net  Intel::DOMAIN      DNS::IN_REQUEST vetted-['tibet' 'financial' 'government' 'cve-2012-0158' 'cryptowall' 'spearphishing' 'grabit' 'poison ivy' 'cve-2014-4114' 'plugx' 'dynamic-dns' 'targeted threats' 'china' 'cve-2010-3333' 'hong kong' 'taiwan' 'targeted attack' 'cve-2014-0497' 'russia' 'espionage']-['securelist.com/blog/research/71713/darkhotels-attacks-in-2015/' 'citizenlab.org/2015/06/targeted-attacks-against-tibetan-and-hong-kong-groups-exploiting-cve-2014-4114/']
```
