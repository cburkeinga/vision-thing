#!/usr/bin/python


import os
#import json
import simplejson as json
from xml.etree import ElementTree
import sys, requests
from jira import JIRA


#parse zap report and send defects to jira
def processfile(inputfile):
        with open(inputfile) as f:
                tree = ElementTree.parse(f)
        f.close()
        root = tree.getroot()
        outputlist = []
        for site in root:
                for alerts in site:
                        for alertitem in alerts:
                                wantthis = 0
                                for child in alertitem:
                                        if (child.tag == 'riskcode') and (int(child.text) > 0):
                                                wantthis = 1
                                        if (child.tag == 'alert'):
                                                prospect = child.text
                                if wantthis == 1:
                                        outputlist.append(prospect)
        outputstring = '\n'.join(outputlist)
        outputvariable = {'fields':{'project':{'key':'BIT'},'summary':'BURP vulnerability','description':outputlist,'issuetype':{'name':'Bug'},'components':[{'id':'10731'}]}}
        jsonoutput = json.dumps(outputvariable)

	print outputstring

	options={'server':'https://bitcon.atlassian.net'}
	jira = JIRA(options=options,basic_auth=('cburke@burkeitconsulting.com','The555th'))
	new_issue = jira.create_issue(project={'key':'BIT'},summary='New issue from Zap Scan',description=outputlist,issuetype={'name':'Bug'})



print 'Start Scanning target' 
#os.system("/Applications/OWASP\ ZAP.app/Contents/MacOS/zap.sh -cmd -quickurl http://127.0.0.1:8008/7659273936349613145/newsnippet.gtl -quickout /Users/charlesburke/appsec/report.xml")
#os.system("/Applications/OWASP\ ZAP.app/Contents/MacOS/zap.sh -cmd -quickurl http://hax.tor.hu/warmup1 -quickout /Users/charlesburke/appsec/report.xml")
print 'Scan completed'
print 'Report results' 

# Report the results
processfile('report.xml')
