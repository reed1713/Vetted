# Tkeywords.py
# author reed3276@gmail.com

#python lib
import re

#local methods
from Tconverter import texttoFile

#global vars
KEYWORD_LISTPATH = 'app/lists/keywords.txt'
DOCPATH = 'app/documents/'

def keywordList(wlfile=KEYWORD_LISTPATH):

    with open(wlfile) as wl:
        newl = []
        for l in wl:
            newl.append(l)
        return newl

def match_keyword(inputfile, folder=DOCPATH):

    '''
    returns a dedup list containing keywords
    '''

    kl = keywordList()
    data = inputfile
    keyw = []
    with open(folder + data, 'r') as f:
        for line in f.readlines():
            for w in kl:
                for m in re.findall(w.replace('\r\n', ''), line, re.IGNORECASE):
                    lowert = m.lower()
                    stript = lowert.strip()
                    keyw.append(stript)
    return list(set(keyw))

#if __name__ == '__main__':