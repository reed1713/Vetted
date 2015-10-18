# IOCextractor.py
# author reed3276@gmail.com

#local methods
from Igenerator import indicatorListofDicts
from Wpuller import geturlResource, downloadedFilename

def iocExtractor(IOCurl):

	'''
	calls a bunch of other functions and returns a list of dictionaries containing IOCs:
	[{'md5' : 'sldkfjsldkfj344334'}, {'domain' : 'whatever.com'}]
	'''
	
	#being called in vetted app
	#geturlResource(IOCurl)

	IOCfilename = downloadedFilename(IOCurl)

	IOClistofdicts = indicatorListofDicts(IOCfilename)

	return IOClistofdicts

#if __name__ == '__main__':

