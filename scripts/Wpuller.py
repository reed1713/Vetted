# Wpuller.py
# author reed3276@gmail.com

#req lib
from urlparse import urlparse
import requests

#pyyhon lib
import re
import feedparser
import datetime
import time

#global vars
DOCPATH = 'app/documents/'

def cleanUrl(url):

    '''
    removes http:// or https:// returns cleaned url for db input.
    '''

    parsed = urlparse(url)
    clean = parsed.netloc + parsed.path

    return clean

def downloadedFilename(url):

    '''
    returns a parsed filename string
    '''

    parsed = urlparse(url)
    clean_parsed = parsed.netloc.replace('.', '_') + parsed.path.replace('/', '_')
    return clean_parsed

def cleangetUrl(url):

    '''
    checks to see if https:// or http:// is in front of the url
    if not it prepends http:// to the front and returns the url
    '''

    findscheme = re.compile(r'[http://|s]{4,8}')

    checkit = re.match(findscheme, url)
    if not checkit:
        cleaned_url = 'http://' + url
        return cleaned_url
    return url

def geturlResource(url, folder=DOCPATH):

    '''
    downloads web resource to the Documents/ dir and returns a url string
    '''

    filename = downloadedFilename(url)

    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.91 Safari/537.36'
    }
    r = requests.get(url, headers=header, stream=True, verify=False)

    with open(folder + filename, 'wb') as f:
        for block in r.iter_content(1024):
            if not block:
                break
            f.write(block)
    return url

def checkfeed(feedsourceurl):

    test = feedparser.parse(feedsourceurl).entries

    for e in test:
        t = e['title']
        l = e['link']
        p = datetime.datetime.fromtimestamp(time.mktime(e['published_parsed']))   
        if t == [] or l == [] or p == []:
            return 'FAIL'
        else:
            return 'SUCCESS'


#if __name__ == '__main__':

