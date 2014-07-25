#!/usr/bin/env python2.7
"""
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Use at your own risk.

Bug fixes/feature improvements/request - please email: blackhole.em@gmail.com

NOTE: This version was modified from its original form located at github.com/blackhole-em/cuckoo2STIX
It has been retooled to convert Cuckoo data into a STIX format able to be imported by CRITs
https://github.com/crits/

"""
import sys
import os
import pymongo
import ConfigParser
import argparse
import time
import datetime
import re
import string
import pprint
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.ttp import TTP, Behavior
from stix.common import StructuredText, InformationSource
from stix.common.related import RelatedTTP
from stix.common.identity import Identity
from stix.ttp.malware_instance import MalwareInstance
import stix.utils
from cybox.core import Observable, Observables
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.common import Hash, Time, ToolInformationList, ToolInformation
import cybox.utils
import netaddr
import log

_l = log.setup_custom_logger('root')

def keepAddresses(networkItems_):
    """
    Return a list that contains only addresses.
    """
    for i in networkItems_[:]:
        try:
            ip = netaddr.IPAddress(i)
        except:
            networkItems_.remove(i)
    return networkItems_

def keepHostNames(networkItems_):
    """
    Return a list that contains only items that are not addresses.
    """
    for i in networkItems_[:]:
        try:
            ip = netaddr.IPAddress(i)
            networkItems_.remove(i)
        except:
            pass
    return networkItems_

def delIfMatchedAddr(ipv4Addresses_, fIpv4Addresses_):
    """
    Delete from list any addresses that are also found in the whitelist file. 
    The netaddr module is used to allow cidr and ranges.
    """
    s1 = netaddr.IPSet(ipv4Addresses_)
    l2 = []
    for i in fIpv4Addresses_[:]:
        m = re.search(r'(.*) \.\.\. (.*)', i)
        if not m:
            l2.append(i)
        else:
            l2 += netaddr.IPSet(netaddr.iter_iprange(m.group(1), m.group(2)))
    s2 = netaddr.IPSet(l2)
    return map(str, list(s1 - s2))

def delIfMatchedHostName(hostNames_, fHostNames_):
    """
    Delete from list any names that are also found in the whitelist file, 
    via regex matching.
    """
    for i in fHostNames_:
        for j in hostNames_[:]:
            if re.match(i + '$', j):
                hostNames_.remove(j)
    return hostNames_

def reFileName(str_):
    """
    Extract file name and prefix from string based on known patterns,
    otherwise leave the file name as is, and the prefix will be 'None'.
    """
    rv = 'None', str_
    m = re.match(r'((?:[a-zA-Z0-9-]){4,})_(.*)$', str_)
    if m:
        rv = m.group(1), m.group(2)
    else:
        m = re.match(r'(\d+-\d+)\.-\.(.*)$', str_)
        if m:
            rv = m.group(1), m.group(2)
    return rv

def fixAddressObject(xml_):
    """
    Search and replace address object tag when there are multiple items in the 
    list, since can't figure out how to do the same using the library. If the 
    address is a single value or there is no address at all, leave alone.
    """
    rv = xml_
    m = re.search(r'(.*<AddressObj:Address_Value condition="Equals")>(.*comma.*)(<.*)', xml_, re.DOTALL)
    if m:
        rv = m.group(1) + ' apply_condition="ANY">' + m.group(2) + m.group(3)
    return rv
    
def fixDomainObject(xml_):
    """
    Search and replace domain name object tag when there are multiple items in the 
    list, since can't figure out how to do the same using the library. If the 
    domain name is a single value or there is no domains at all, leave alone.
    """
    rv = xml_
    m = re.search(r'(.*<DomainNameObj:Value)>(.*comma.*)(<.*)', xml_, re.DOTALL)
    if m:
        rv = m.group(1) + ' condition="Equals" apply_condition="ANY">' + m.group(2) + m.group(3)
    return rv

def genStixDoc(
        outputDir_,
        targetFileSha1_,
        targetFileSha256_,
        targetFileSha512_,
        targetFileSsdeep_,
        targetFileMd5_,
        targetFileSize_,
        targetFileName_,
        ipv4Addresses_,
        hostNames_):
    """
    Generate Stix document from the input values. The doc structure is the file
    object along with the related network items: addresses, domain names. Output
    is written to files, which are then wrapped with taxii and uploaded using a 
    separate script.
    """
    parsedTargetFileName = reFileName(targetFileName_)[1]
    parsedTargetFilePrefix = reFileName(targetFileName_)[0]
    stix.utils.set_id_namespace({"http://www.nickdriver.com/cuckoo2CRITs" : "cuckoo2CRITs"})
    NS = cybox.utils.Namespace("http://www.nickdriver.com/cuckoo2CRITs", "cuckoo2CRITs")
    cybox.utils.set_id_namespace(NS)
    stix_package = STIXPackage()

    stix_header = STIXHeader()
    stix_header.title = 'File: ' + parsedTargetFileName + ' with the associated hashes, network indicators'
    stix_header.description = 'File: ' + parsedTargetFileName + ' with the associated hashes, network indicators'
    stix_package.stix_header = stix_header

    #Will take this out later
    # Create the ttp
    malware_instance = MalwareInstance()
    malware_instance.add_name(parsedTargetFileName)
    malware_instance.description = targetFileSha1_
    ttp = TTP(title='TTP: ' + parsedTargetFileName)
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware_instance)
    #stix_package.add_ttp(ttp)
    
    #Trying to create an array that will be added later...
    stix_observables = []
    
    #This works - leaving intact until the new portion works
    '''
    # Create the indicator for the ipv4 addresses
    ipv4Object = Address(ipv4Addresses_, Address.CAT_IPV4)
    #stix_msg['stix_observables'].extend(Observables([ipv4Object]))
    stix_observables.extend([ipv4Object])
    '''
    for ip in ipv4Addresses_:
		ipv4Object = Address(ip, Address.CAT_IPV4)
		stix_observables.extend([ipv4Object])
    
    
    '''
    #This works - leaving intact until the new portion works
    # Create the indicator for the domain names
    domainNameObject = DomainName()
    domainNameObject.value = hostNames_
    '''
    for name in hostNames_:
		domainNameObject = DomainName()
		domainNameObject.value = name
		stix_observables.extend([domainNameObject])
		
    

    
    # Create the observable for the file
    fileObject = File()
    fileObject.file_name = parsedTargetFileName
    #fileObject.file_name.condition = 'Equals'
    fileObject.size_in_bytes = targetFileSize_
    #fileObject.size_in_bytes.condition = 'Equals'
    fileObject.add_hash(Hash(targetFileSha1_, type_='SHA1', exact=True))
    fileObject.add_hash(Hash(targetFileSha256_, type_='SHA256', exact=True))
    fileObject.add_hash(Hash(targetFileSha512_, type_='SHA512', exact=True))
    fileObject.add_hash(Hash(targetFileSsdeep_, type_='SSDEEP', exact=True))
    fileObject.add_hash(Hash(targetFileMd5_, type_='MD5', exact=True))
    
    stix_observables.extend([fileObject])
    
    
    stix_package.observables = Observables(stix_observables)
    
    #DEBUG
    #stagedStixDoc = stix_package.to_xml()
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(stagedStixDoc)
		
    #print "stix_observables list"

    #pp.pprint(stix_observables)
    
    '''
    #VERY BASIC STIX ATTEMPT - THIS WORKS!
    a = Address("1.2.3.4", Address.CAT_IPV4)
    d = DomainName()
    d.value = "cybox.mitre.org"
    stix_package.observables = Observables([a, d])
    #concensus - Observable does not work - ObservableS does
    '''
	
	
	###UNCOMMENT THIS WHEN DONE###
	
    
    stagedStixDoc = stix_package.to_xml()
    stagedStixDoc = fixAddressObject(stagedStixDoc)
    stagedStixDoc = fixDomainObject(stagedStixDoc)
    today = datetime.datetime.now()
    now = today.strftime('%Y-%m-%d_%H%M%S')
    if not os.path.exists(outputDir_):
        os.makedirs(outputDir_)
    with open (outputDir_ + '/' + now + '-' + targetFileSha1_ + '.stix.xml', 'a') as myfile:
        myfile.write(stagedStixDoc)
    _l.debug('Wrote file: ' + now + '-' + targetFileSha1_ + '.stix.xml')
    
    return

def main():
    """
    Retrieve network indicators from mongodb, used by cuckoo. Pass to genStixDoc 
    to create the stix doc. Handle de-dup and filter lists for indicators, as 
    well as stix items created in previous runs.
    """
    ap = argparse.ArgumentParser()
    apg = ap.add_mutually_exclusive_group()
    apg.add_argument('--job-id', dest='jobId', default='', help='Cuckoo job id to query.')
    apg.add_argument('--md5', dest='md5', default='', help='File md5 hash to query.')
    apg.add_argument('--sha1', dest='sha1', default='', help='File sha1 hash to query.')
    apg.add_argument('--sha256', dest='sha256', default='', help='File sha256 hash to query.')
    apg.add_argument('--sha512', dest='sha512', default='', help='File sha512 hash to query.')
    args = ap.parse_args()
    config = ConfigParser.ConfigParser()
    config.read('app.conf')
    conn = pymongo.MongoClient(config.get('mongo','dbUrl'))
    with open(config.get('filterOut','fIpv4Addresses'), 'r+') as fIpv4AddressesFH:
                fIpv4Addresses = [line.rstrip('\n') for line in fIpv4AddressesFH]
    fIpv4AddressesFH.closed
    with open(config.get('filterOut','fHostNames'), 'r+') as fHostNamesFH:
                fHostNames = [line.rstrip('\n') for line in fHostNamesFH]
    fHostNamesFH.closed
    with open(config.get('filterOut','fSeenEntries'), 'w+') as fSeenEntriesFH:
                fSeenEntries = [line.rstrip('\n') for line in fSeenEntriesFH]
    fSeenEntriesFH.closed

    networkItems = []
    ipv4Addresses = []
    hostNames = []
    _l.info('Starting...')

    fSeenEntriesFH = open(config.get('filterOut','fSeenEntries'), 'a', 0)
   
    cfg_collections = config.get('mongo','dbCollectionNames')
    if ',' in cfg_collections:
        db_collection_names = cfg_collections.split(',')
    else:
        db_collection_names = [cfg_collections]
    
    cuckoo_names = config.get('dbsList','cuckoo')
    if ',' in cuckoo_names:
        cuckoo_servers = cuckoo_names.split(',')
    else:
        cuckoo_servers = [cuckoo_names]

    for dbkey, dbs in enumerate(cuckoo_servers):
        db = conn[dbs]
        mongo_collection = getattr(db, db_collection_names[dbkey])
        _l.debug('Connected to data source.')

        # Get a list of file names and hashes from db
        if args.jobId:
            cs = mongo_collection.aggregate([{"$match": {"info.id": int(args.jobId)}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        elif args.md5:
            cs = mongo_collection.aggregate([{"$match": {"target.file.md5": args.md5}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        elif args.sha1:
            cs = mongo_collection.aggregate([{"$match": {"target.file.sha1": args.sha1}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        elif args.sha256:
            cs = mongo_collection.aggregate([{"$match": {"target.file.sha256": args.sha256}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        elif args.sha512:
            cs = mongo_collection.aggregate([{"$match": {"target.file.sha512": args.sha512}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        else:
            cs = mongo_collection.aggregate([{"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                         "targetFileSha256": "$target.file.sha256",
                                                         "targetFileSha512": "$target.file.sha512",
                                                         "targetFileSsdeep": "$target.file.ssdeep",
                                                         "targetFileMd5": "$target.file.md5",
                                                         "targetFileSize": "$target.file.size",
                                                         "targetFileName": "$target.file.name"}}}])
        _l.debug('Executed initial aggregation query.')
        for i in cs['result']:
            try:
                # Get all network indicators: addresses and names
                networkItems[:] = []
                ipv4Addresses[:] = []
                hostNames[:] = []
                networkUdpSrc = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.udp.src')
                networkUdpDst = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.udp.dst')
                networkIcmpSrc = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.icmp.src')
                networkIcmpDst = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.icmp.dst')
                networkTcpSrc = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.tcp.src')
                networkTcpDst = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.tcp.dst')
                networkDnsAnswersData = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.dns.answers.data')
                networkDomainsIp = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.domains.ip')
                networkHttpHost = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.http.host')
                networkHosts = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.hosts')
                networkDnsRequest = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.dns.request')
                networkDomainsDomain = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('network.domains.domain')
    
                # Aggregate all found items and remove duplicates and empty
                networkItems += networkUdpSrc + networkUdpDst + networkIcmpSrc + \
                    networkIcmpDst + networkTcpSrc + networkTcpDst + \
                    networkDnsAnswersData + networkDomainsIp + networkHttpHost + \
                    networkHosts + networkDnsRequest + networkDomainsDomain
                networkItems = list(set(networkItems))
                networkItems = filter(None, networkItems)
                
                # Split into one list for addresses and one for host names
                ipv4Addresses = keepAddresses(networkItems[:])
                hostNames = keepHostNames(networkItems[:])
    
                # Delete addresses and host names if in whitelist files
                ipv4Addresses = delIfMatchedAddr(ipv4Addresses, fIpv4Addresses)
                hostNames = delIfMatchedHostName(hostNames, fHostNames)
    
                # Get file names
                targetFileName = mongo_collection.find(
                    {
                        "target.file.sha1": i['_id']['targetFileSha1'],
                        "target.file.sha256": i['_id']['targetFileSha256'],
                        "target.file.sha512": i['_id']['targetFileSha512'],
                        "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                        "target.file.md5": i['_id']['targetFileMd5'],
                        "target.file.size": i['_id']['targetFileSize'],
                        "target.file.name": i['_id']['targetFileName']}).distinct('target.file.name')
               
                #BEGIN DEBUG SECTION
                '''
                pp = pprint.PrettyPrinter(indent=4)
                print "IPv4 Addresses"
                pp.pprint(ipv4Addresses)
                print "HOSTNAMES"
                pp.pprint(hostNames)
                #pp.pprint(str(i['_id']['targetFileSha1']))
                print "ANALYSIS"
                #pp.pprint(i['_id']['targetFileSha1'])
                pp.pprint(i)
                '''
                
                #####EXAMPLE OUTPUT#####
                '''
                IPv4 Addresses
				[   '23.207.9.92',
					'157.56.141.102',
					'165.254.57.27',
					'192.168.1.117',
					'192.168.1.119',
					'192.168.1.121',
					'192.168.1.124',
					'192.168.1.201',
					'192.168.1.255',
					'209.8.115.63',
					'239.255.255.250']
					
				HOSTNAMES
				[u'watson.microsoft.com', u'www.msftncsi.com', u'armmf.adobe.com']
				
				ANALYSIS
				{   u'_id': {   u'targetFileMd5': u'f6a390105740b99a211e51a5b9f018ea',
								u'targetFileName': u'requirements.pdf.scr',
								u'targetFileSha1': u'e284ba4a06d1dc2e211aceaf9bce14803f094cb6',
								u'targetFileSha256': u'd0419cd6f455c56ae77657e3590508a13b298395fce50609daf7e09ce28de63c',
								u'targetFileSha512': u'8957af673a1272cc2eb34fb5f699d475df7c6af84f77c8d169b22225ad8b6d64c36ee150eb3982fb73aafd3c8fb5047fe752a7f01976a519e861353495ddb445',
								u'targetFileSize': 105984,
								u'targetFileSsdeep': u'1536:OVfPLtI38adjA3wkJUOoMiqcy8hnzkqUJC2NjIFwBSjh36kJJ4cq:OVfPLtkqUNhby8hnz/cDNjlSjh33q'}}

                '''
                #Taking out for debugging b/c we don't want to make any xml's nor write to the 
                #seen-entries log yet, just print to screen
                
                #'''
                
                # Call the function to create the output, check if seen before first
                if str(i['_id']['targetFileSha1']) + ',' + \
                    str(i['_id']['targetFileSha256']) + ',' + \
                    str(i['_id']['targetFileSha512']) + ',' + \
                    str(i['_id']['targetFileSsdeep']) + ',' + \
                    str(i['_id']['targetFileMd5']) + ',' + \
                    str(i['_id']['targetFileSize']) not in str(fSeenEntries):                        
                        if ipv4Addresses or hostNames:	#Does this need to be here? What if there were no callouts?
                            genStixDoc(config.get('output','outputDir'),
                                       str(i['_id']['targetFileSha1']),
                                       str(i['_id']['targetFileSha256']),
                                       str(i['_id']['targetFileSha512']),
                                       str(i['_id']['targetFileSsdeep']),
                                       str(i['_id']['targetFileMd5']),
                                       str(i['_id']['targetFileSize']),
                                       i['_id']['targetFileName'],
                                       ipv4Addresses,
                                       hostNames)
                            # Write to file so that we can read back in as filter later
                            fSeenEntriesFH.write(str(i['_id']['targetFileSha1']) + ',' + \
                                str(i['_id']['targetFileSha256']) + ',' + \
                                str(i['_id']['targetFileSha512']) + ',' + \
                                str(i['_id']['targetFileSsdeep']) + ',' + \
                                str(i['_id']['targetFileMd5']) + ',' + \
                                str(i['_id']['targetFileSize']) + '\n')
                            _l.debug('Updated SeenEntries file with: ' + \
                                str(i['_id']['targetFileSha256']) + ',' + \
                                str(i['_id']['targetFileSha512']) + ',' + \
                                str(i['_id']['targetFileSsdeep']) + ',' + \
                                str(i['_id']['targetFileMd5']) + ',' + \
                                str(i['_id']['targetFileSize']) + \
                                ' since content has been written to stix file.\n')
               
               #'''                 
               
               #END DEBUG SECTION
               
                                
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                _l.error('Row failed due to: ' + str(e) + "\n\n" + str(tb) + "\n\n" + str(repr(i)))
        conn.disconnect()
    fSeenEntriesFH.closed
    _l.info('Ended.')

if __name__ == "__main__":
    main()
