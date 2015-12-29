# Igenerator.py
# author reed3276@gmail.com

#python lib
import re

#local methods
from Tconverter import *
from app import db
#from app.models import Settings

#global vars
WHITELISTPATH = 'app/lists/whitelist.txt'
DOCPATH = 'app/documents/'

# TEST = db.session.query(Settings.whitelistpath).first()
# print TEST

# some regex pulled from https://github.com/armbues/ioc-parser/blob/master/patterns.ini
# and a lot of the whitelist examples are pulled from https://github.com/armbues/ioc-parser/tree/master/whitelists

#BRO Intel Type compat
#URL type intentionally left out "http://"" prefix to match BRO intel type format

regexdict = {
'FILE_HASH' : r"^[a-f0-9]{64}$|^[a-f0-9]{40}$|^[a-f0-9]{32}$", #MD5, SHA1, SHA256
'ADDR' : r"((?:(?:[12]\d?\d?|[1-9]\d|[1-9])\[?\.\]?){3}(?:[12]\d?\d?|[\d+]{1,2}))",
'DOMAIN' : r"[a-z0-9\[\.\]]+(?:[\-|\.][a-z0-9]+)*\[?\.\]?(?:MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|TEL|XXX)",
'EMAIL' : r"[a-z0-9\_\.\+\-]+@[a-z0-9\-]*\[?\.\]?(?:MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|TEL|XXX)",
'FILE_NAME' : r"([a-z0-9-_\.]+\.(?:exe|dll|bat|sys|htm|html|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))",
'URL' : r"[a-z0-9]+(?:[\-|\.][a-z0-9]+)*\[?\.\]?(?:MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|TEL|XXX)\/[a-z0-9\.\-\?=#%\/_&]*",
'CERT_HASH' : r"^[0-9a-f:]{59}$",
}

def whiteList(wlfile=WHITELISTPATH):

    with open(wlfile) as wl:
        newl = []
        for l in wl:
            newl.append(l)
        return newl

def notinWhitelist(match, wl):

    wlist = whiteList()

    interesting = True
    for item in wlist:
        if re.search(item.replace('\r\n', ''), match, re.IGNORECASE):
            interesting = False
    return interesting

def indicatorGen(inputfile, folder=DOCPATH):

    '''
    yields a generator object containing atomic indicator 
    dictionary objects {indicator_type : indicator_value}
    '''

    wl = whiteList()
    data = texttoFile(inputfile)

    with open(folder + data, 'r') as f:
        for line in f.readlines():
            for key, value in regexdict.iteritems():
                for m in re.findall(value, line, re.IGNORECASE):
                    if notinWhitelist(m, wl):
                        indicatordict = {key : m}
                        yield indicatordict

def indicatorListofDicts(IOCFile):

    '''
    returns a unique list of dictionaries containing atomic indicator
    dictionary objects [{indicator_type : indicator_value}, ...]
    '''

    out = indicatorGen(IOCFile)
    diction = list(out)
    
    if diction:
        unique_sets = set(frozenset(d.items()) for d in diction)
        unique_dicts = [dict(s) for s in unique_sets]
        sortit = sorted(unique_dicts)
        return sortit
    else:
        return

#if __name__ == '__main__':


