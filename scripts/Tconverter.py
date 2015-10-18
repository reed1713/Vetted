# Tconverter.py
# author reed3276@gmail.com

# req lib
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from cStringIO import StringIO
from docx import opendocx, getdocumenttext
from bs4 import BeautifulSoup

#python lib
import os

DOCPATH = 'app/documents/'

def convertpdftoText(path):

    '''
    pulled from the below link, and modified to output a string
    http://stackoverflow.com/questions/5725278/python-help-using-pdfminer-as-a-library
    '''

    rsrcmgr = PDFResourceManager()
    retstr = StringIO()
    codec = 'utf-8'
    laparams = LAParams()
    device = TextConverter(rsrcmgr, retstr, codec=codec, laparams=laparams)
    fp = file(path, 'rb')
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    password = ""
    maxpages = 0
    caching = True
    pagenos=set()

    for page in PDFPage.get_pages(fp, pagenos, maxpages=maxpages, password=password,caching=caching, check_extractable=True):
        interpreter.process_page(page)

    fp.close()
    device.close()
    str = retstr.getvalue()
    retstr.close()
    
    return str
 
def doctoText(filepath):

    '''
    returns a string of text from the input file. created the if statement
    for future file formats. link below provided partial code.
    http://davidmburke.com/2014/02/04/python-convert-documents-doc-docx-odt-pdf-to-plain-text-without-libreoffice/
    '''

    if filepath[-4:] == ".pdf":
        return convertpdftoText(filepath)
    elif filepath[-5:] == ".docx":
        document = opendocx(filepath)
        paratextlist = getdocumenttext(document)
        newparatextlist = []
        for paratext in paratextlist:
            newparatextlist.append(paratext.encode("utf-8"))
        return '\n\n'.join(newparatextlist)
    else:
        with open(filepath, 'rb') as myfile:
            try:
                #cleans html, removes tags
                htmldata = myfile.read()
                edata = htmldata.decode('utf-8', 'strict')
                raw = BeautifulSoup(edata).get_text()
                cleanedhtml = raw.encode('utf-8', 'strict')
                return cleanedhtml
            except:
                data = myfile.read()
                return str(data)

def texttoFile(filen, folder=DOCPATH):

    '''
    takes the return text from doctoText, writes to file. returns file object
    '''

    outfile = filen + '.txt'
    writedoc = doctoText(folder + filen)
    if not os.path.exists(folder + outfile):
        with open(folder + outfile, 'w') as outfp:
            outfp.write(writedoc)
            return outfile
    else:
        return outfile

#if __name__ == '__main__':

