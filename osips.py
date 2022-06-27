#!/usr/bin/env python3
# Script: osips.py
# Purpose:  Collect IP addresses from a folder and check them against TOR, WhoIs and location
#           Export files with details (csv and json), file with index (csv) and file with locations (kml)
# Created by: Ciprian Lazar

#import region
import ipaddress
import re
import sys
import os
import requests
import argparse
import simplekml
from glob import glob
from csv import DictWriter
from onion_py.manager import Manager
from onion_py.caching import OnionSimpleCache
from datetime import datetime
from ipwhois import IPWhois
from pprint import pprint

# Function GetArguments
# Purpose: Get command line arguments or interactive values when the corresponding argument is not defined
def GetArguments():
    parser = argparse.ArgumentParser(description='This script scans every file from a given folder recursively, extracts every IPv4 and IPv6 address, filters out the public IP addresses and then queries these IPs against TOR relays, WhoIs service and Location service. It outputs 4 files: a CSV file and a JSON file with all details of the IP addresses, a CSV file containing an index of every found IP address and a KML file with all the locations gathered.')
    parser.add_argument('-F', '--inputFolder', help='A folder containing files with IPs (log files, email files, text files etc). The IPs can be IPv4 and/or IPv6 and can be placed anywhere in the files. The script will parse every file in the folder and will scan for every IP')
    parser.add_argument('-f', '--inputFile', help='Use this option to scan only one file instead of a folder with files. The file can be any text file that contains IP addresses (log files, email files, text files etc.)')
    parser.add_argument('-p', '--inputFilesPattern', help='Enter the pattern to use for the files in the input folder. Example: * for all files, *.txt for text files.')
    parser.add_argument('-o', '--outputFilesName', help='The name for the output files, WITHOUT EXTENSION. 4 different files will be created with this name: a CSV file storing the IP details, an index file storing the IP indexes, a JSON file storing the details and a KML file storing the locations.')
    parser.add_argument('-t', '--checkTor', choices=['y', 'n', 'Y', 'N'], help='Specify if you want to check every public IP address against the TOR relays IP addresses')
    parser.add_argument('-w', '--checkWhoIs', choices=['y', 'n', 'Y', 'N'], help='Specify if you want to extract WhoIs information for every public IP address')
    parser.add_argument('-l', '--checkLocations', choices=['y', 'n', 'Y', 'N'], help='Specify if you want to geocode every public IP address and extract location info using https://reallyfreegeoip.org')
    parser.add_argument('-locationEndpoint', help='Default REST endpoint for location is "https://reallyfreegeoip.org/json/<IP>". You can specify a diffrent end point, includding <IP> placeholder. The result must be in JSON and must include the following fields: country_name, region_code, region_name, city, zip_code, time_zone, latitude, longitude, metro_code')
    args = parser.parse_args()
    ## The arguments are optional. If an argument is not specified, then the script asks the value interactively
    ## If no input folder was specified, ask it interactively
    if bool(args.inputFolder):
        print(f'Input folder: {args.inputFolder}')
    else:
        if bool(args.inputFile):
            print(f'Input file: {args.inputFile}')
        else:
            args.inputFolder = input('Path to input folder (Leave empty if you want to parse a single file): ')
    ## If no input folder and no input file was specified, ask for input file interactively
    if not(bool(args.inputFolder)):
        if bool(args.inputFile):
            print(f'Input file {args.inputFile}')
        else:
            args.inputFile = input('Path to input file: ')
    ## If no input pattern was specified, ask it interactively
    if (bool(args.inputFilesPattern)):
        print(f'Pattern for input files: {args.inputFilesPattern}')
    else:
        if not(bool(args.inputFile)):
            args.inputFilesPattern = input('Enter pattern for input files (<Enter> for *): ') or '*'
    ## If no CSV file was specified, ask it interactively
    if bool(args.outputFilesName):
        print(f'Output files name (without extension): {args.outputFilesName}')
    else:
        args.outputFilesName = input('Path and name for output files (without extension): ')
    if not (bool(args.checkTor)):
        args.checkTor = input('Check IPs against TOR relays ([Y]/N)? ') or 'Y'
    ## IF checkWhoIs was not specified as argument, ask for it interactively
    if not (bool(args.checkWhoIs)):
        args.checkWhoIs = input('Check IPs with WhoIs service ([Y]/N)? ') or 'Y'
    ## IF checkLocations was not specified as argument, ask for it interactively
    if not (bool(args.checkLocations)):
        args.checkLocations = input('Check IPs location at reallyfreegeoip.org ([Y]/N)? ') or 'Y'
    if not (bool(args.locationEndpoint)):
        args.locationEndpoint = 'https://reallyfreegeoip.org/json/<IP>'
    return args
# end GetArguments


# Function: ExtractIpsFromFolder
# Purpose: Go to every file from a specified folder and call the function that extracts IP addresses from the file (ExtractIps)
# Arguments:
#       folderPath - the folder containing the files with IP addresses
#       ips        - the dictionary with IPs that must be updated. It can be empty or with IPs
#       outputIndexFile - the file with the index of found IPs
# Returns:
#       ips - dictionary with extracted IPs
#       ipCnt - number of extracted IPs
def ExtractIpsFromFolder(folderPath, filePattern, ips, outputIndexFile):
    ipCnt = 0
    ## Recursively extract all files with the provided pattern
    fullPath = os.path.join(folderPath, "**", filePattern)  ## This will work in both Linux and Windows
    inputFiles = [afile for afile in glob(fullPath, recursive=True) if not os.path.isdir(afile)]
    for currFile in inputFiles:
        Log(f'Processing file {currFile}...')
        ips, ipCnt = ExtractIps(currFile, ipCnt, ips, outputIndexFile)
    return ips, ipCnt
# end ExtractIpsFromFolder


# Function: ExtractIps
# Purpose: Parse the entire file and extract, using regex, every IP address (both IPv4 and IPv6)
# Arguments:
#       inputFile - a text file that may contain IP addresses
#       ipCnt     - current extracted IPs count
#       ips       - the dictionary with IPs that must be updated. It can be empty or with IPs
#       outputIndexFile - the file with the index of found IPs
# Returns:
#       ips - dictionary with extracted IPs
#       ipCnt - number of extracted IPs
def ExtractIps(inputFile, ipCnt, ips, outputIndexFile):
    ## Define patterns
    #ipv4pattern = r'(?:(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\.){3}(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])'
    ipv4simple = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Define IPv6 patterns
    IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    IPV4ADDR = r'\b(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')\b'
    IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
    IPV6GROUPS = (
        r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
        r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
        r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
        r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
        r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
        r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
        r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
        IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
        r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
        r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
        r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
        r'(?:' + IPV6SEG + r':){1,6}:?[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    )
    IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match

    try:
        with open(inputFile, 'rt') as inFile:
            # read the file line by line without loading it all into memory
            lineNo = 1
            for line in inFile:
                matches = re.findall(ipv4simple, line, re.IGNORECASE)           ## Match against an IPv4 pattern (use the simple patter because it is safer. Invalid IPs will be descarded later by try-except)
                matches = matches + re.findall(IPV6ADDR, line, re.IGNORECASE)   ## Add matches against an IPv6 pattern
                for match in matches:
                    try:
                        currentIp = ipaddress.ip_address(match) ## If the IP in invalid, an exception is raised here and the IP is not processed
                        WriteLocation(match, inputFile, lineNo, outputIndexFile)
                        if match in ips:    ## If the IP was already found, update its count number
                            ips[match]['Count'] = ips[match].get('Count', 0) + 1
                        else:   ## If the found IP is new (it's the first time when it is found)
                            ipCnt = ipCnt + 1
                            ips[match] = {'No': ipCnt,
                                        'IP': currentIp,
                                        'Count': 1,
                                        'Type': f'IPv{currentIp.version}',
                                        'IP Exploded': currentIp.exploded,
                                        'Decimal': currentIp._ip}
                            if currentIp.is_global:
                                ips[match]['Public'] = 'Public'
                    except:
                        ## It is not a valid address
                        pass
                lineNo = lineNo + 1
    except:
        Log(f'File {inputFile} cannot be read as text.')
    return ips, ipCnt
# end ExtractIps


# Function: CheckIpsAgainstTor
# Purpose: Check every public IP address to see if it is a TOR exit node
# Arguments:
#       ips       - the dictionary with IPs that must be updated. It can be empty or with IPs
#       totalPublic - the number of public addresses found
# Returns:
#       ips - dictionary with extracted IPs updated with TOR information
def CheckIpsAgainstTor(ips, totalPublic):
    cnt = 0
    manager = Manager(OnionSimpleCache())
    manager.OOO_VERSION_MAJOR = 8 ## Hack to fool the version of the module
    s = manager.query('summary')

    for currIp in ips:
        if ips[currIp].get('Public','') != 'Public':
            continue  ## If the IP is not public, do not search it. Skip to next
        cnt = cnt + 1
        Log(f'TOR Lookup {cnt}/{totalPublic}: {currIp}')
        for relay in s.relays: ## Go through all the TOR relays
            for address in relay.addresses: ## Go through all the IPs of the relay
                if ips[currIp]['Type'] == 'IPv4': ## If the current IP is IPv4, compare it with the TOR ip as v4
                    try:
                        if ips[currIp]['IP'] == ipaddress.IPv4Address(address):
                            ips[currIp]['TorNode'] = 'TOR'
                            ips[currIp]['TorNickname'] = relay.nickname
                            continue
                    except:
                        pass
                else: ## If the current IP is IPv6, compare it with the TOR ip as v6
                    try:
                        if ips[currIp]['IP'] == ipaddress.IPv6Address(address):
                            ips[currIp]['TorNode'] = 'TOR'
                            ips[currIp]['TorNickname'] = relay.nickname
                            continue
                    except:
                        pass
    return ips
# end CheckIpsAgainstTor


# Function: IPWhoisLookup
# Purpose: Check every public IP address against a WhoIs service to extract info like ASN, Country, Description, Contact info etc
# Arguments:
#       ips       - the dictionary with IPs that must be updated. It can be empty or with IPs
#       totalPublic - the number of public addresses found
# Returns:
#       ips - dictionary with extracted IPs updated with WhoIs information
def IPWhoisLookup(ips, totalPublic):
    cnt = 0
    for currIp in ips:
        if ips[currIp].get('Public','') != 'Public':
            continue  ## If the IP is not public, do not search it. Skip to next
        cnt = cnt + 1
        Log(f'WhoIs Lookup {cnt}/{totalPublic}: {currIp}')
        try:
            data = IPWhois(ips[currIp]['IP']).lookup_rdap() ## Extract all the information about the IP (IPWHois.lookup_rdap())
            ips[currIp]['ASN'] = data['asn']
            ips[currIp]['ASN Registry'] = data['asn_registry']
            ips[currIp]['Country Code'] = data['asn_country_code']
            ips[currIp]['Date'] = data['asn_date']
            ips[currIp]['Description'] = data['asn_description']
            ips[currIp]['Name'] = data['network']['name']
            for val in data['objects'].values():
                ips[currIp]['Contact Name'] = val['contact']['name']
                if bool(val['contact']['address']):
                    for val2 in val['contact']['address']:
                        ips[currIp]['Contact'] = val2['value']
                        break  # Only read the first element
                if bool(val['contact']['email']):
                    for val2 in val['contact']['email']:
                        ips[currIp]['Email'] = val2['value']
                        break  # Only read the first element
                if bool(val['contact']['phone']):
                    for val2 in val['contact']['phone']:
                        ips[currIp]['Phone'] = val2['value']
                        break  # Only read the first element
                break # Only read the first element
        except:
            Log(f'Error at IP address lookup: {sys.exc_info()[0]}')
    return ips
# end IPWhoisLookup


# Function: RequestInfoFromRestEndpoint
# Purpose: Check every public IP address against a REST API service to extract info about location like Country, Region, City, GPS etc
# Arguments:
#       ips       - the dictionary with IPs that must be updated. It can be empty or with IPs
#       totalPublic - the number of public addresses found
# Returns:
#       ips - dictionary with extracted IPs updated with location information
def RequestInfoFromRestEndpoint(ips, apiEndpoint, totalPublic):
    cnt = 0
    for currIp in ips:
        if ips[currIp].get('Public','') != 'Public':
            continue ## If the IP is not public, do not search it. Skip to next
        url = apiEndpoint.replace('<IP>', currIp) ## Build the URL to be queried (https://reallyfreegeoip.org/json/<IP>)
        cnt = cnt + 1
        Log(f'Rest Enpoint Lookup {cnt}/{totalPublic}: {currIp}')
        try:
            data = requests.get(url).json()  ## Make the request that expects a json response
            ips[currIp]['Country Code'] = data['country_code']
            ips[currIp]['Country'] = data['country_name']
            ips[currIp]['Region code'] = data['region_code']
            ips[currIp]['Region'] = data['region_name']
            ips[currIp]['City'] = data['city']
            ips[currIp]['Zip Code'] = data['zip_code']
            ips[currIp]['Time Zone'] = data['time_zone']
            ips[currIp]['Latitude'] = data['latitude']
            ips[currIp]['Longitude'] = data['longitude']
            ips[currIp]['Metro Code'] = data['metro_code']
        except:
            Log(f'Error at Rest endpoint lookup: {sys.exc_info()[0]}')
    return ips
# end RequestInfoFromRestEndpoint


# Function: WriteLocation
# Purpose: Append a line with info into the index file
# Arguments:
#       ipstr           - IP address found, as string
#       fileName        - The name of the file in which the IP was found
#       lineNo          - The line number at which the IP was found
#       outputIndexFile - The index file in which the information is to be appended
def WriteLocation(ipstr, fileName, lineNo, outputIndexFile):
    with open(outputIndexFile, 'a') as indexFile:
        indexFile.write(f'{ipstr}, {lineNo}, {fileName}\n')
# end WriteLocation


# Function: WriteDictToCSV
# Purpose: Writes the dictionary with information about IPs to a CSV file
# Arguments:
#       csvFileName       - The CSV file in which to write the dictionary information
#       dictOfDict        - The dictionary of IPs with all the information
def WriteDictToCSV(csvFileName, dictOfDict):
    #TODO: Logic to parse dynamic list of fields (when other rest endpoints are queried)
    fieldNames = ['No', 'IP', 'Count', 'Type', 'Public','TorNode', 'TorNickname',
                'Country Code', 'Country', 'Region code', 'Region', 'City', 'Zip Code',
                 'Latitude', 'Longitude', 'IP Exploded', 'Decimal', 'Metro Code', 'Time Zone',
                 'ASN', 'ASN Registry', 'Country Code', 'Date', 'Description', 'Name', 'Contact Name',
                 'Contact', 'Phone', 'Email']
    if bool(dictOfDict):
        try:
            with open(csvFileName, 'wt', newline='', encoding='utf-8') as csvFile:
                if not fieldNames: ## If the fieldNames was not defined, build it from the keys of the first element
                    fieldNames = dictOfDict[next(iter(dictOfDict))].keys()
                writer = DictWriter(csvFile, fieldnames=fieldNames, restval='', extrasaction='raise')
                writer.writeheader()
                for curKey in dictOfDict.keys(): ## Write all IPs info to the CSV file
                    writer.writerow(dictOfDict[curKey])
        except IOError:
            Log("I/O error when writing results to csv")
    else:
        Log("No results found")
# end WriteDictToCSV


# Function: WriteIpsKml
# Purpose: Writes a KML file with al extracted locations
# Arguments:
#       ips       - The dictionary with all IP details
#       outputFilePath        - The name of the output KML file
def WriteIpsKml(ips, outputFilePath):
    points_kml = simplekml.Kml()
    for currKey in ips.keys():
        if ips[currKey].get('Longitude','') != '' and ips[currKey].get('Latitude','') != '':
            points_kml.newpoint(name=f'{currKey} - {ips[currKey]["Country"]}',
                                coords=[(ips[currKey]['Longitude'], ips[currKey]['Latitude'])],
                                description=f'{ips[currKey].get("City","")} - {ips[currKey].get("Name","")} - {ips[currKey].get("Contact Name","")}')
    points_kml.save(outputFilePath)
# end WriteIpsKml

# Function: Log
# Purpose: Output a text to the console out, appended with the current time
# Arguments:
#       message       - The message that must be written to the console out
def Log(message):
    print(f'{datetime.now().strftime("%H:%M:%S")}> {message}')
# end Log


########################### MAIN ########################################
# Function: main
# Purpose: The startup function of the script
def main():
    ## Some variables to hold data
    ips = {}
    ipCnt = 0

    ## Get the folder paths, output file names, the queries to run from arguments or interactively
    args = GetArguments()
    # args.locationEndpoint = 'https://reallyfreegeoip.org/json/<IP>'

    ## Initialize the index file in which to write the locations of found IPs
    with open(args.outputFilesName + '_index.csv', 'wt', newline='') as indexFile:
        indexFile.write(f'IP, LineNo, FileName\n')

    Log('Started')
    ## Start processing a folder or a file, according to the input of the user
    if bool(args.inputFolder):
        ips, ipCnt = ExtractIpsFromFolder(args.inputFolder, args.inputFilesPattern, ips, args.outputFilesName + '_index.csv')
    else:
        ips, ipCnt = ExtractIps(args.inputFile, ipCnt, ips, args.outputFilesName + '_index.csv')

    ## Calculate some statistics to output to the screen (console out)
    totalIPs = 0
    totalPublic = 0
    totalIPv4 = 0
    totalIPv6 = 0
    for ipAddress in ips:
        totalIPs = totalIPs + ips[ipAddress]['Count']
        totalPublic = totalPublic + (1 if ips[ipAddress].get('Public','') == 'Public' else 0)
        if ips[ipAddress]['Type'] == 'IPv4':
            totalIPv4 = totalIPv4 + 1
        else:
            totalIPv6 = totalIPv6 + 1
    Log(f'Finished extracting IP addresses.\n\tTotal IP addresses: {totalIPs}\n\tUnique IP addresses: {len(ips)}\n\tIPv4 addresses: {totalIPv4}\n\tIPv6 addresses: {totalIPv6}\n\tPublic addresses: {totalPublic}')

    ## Check every public IP address against the WhoIs service
    if bool(ips) and args.checkWhoIs.upper() == 'Y':
        Log(f'Looking up the IP addresses against IPWhois...')
        IPWhoisLookup(ips, totalPublic)

    ## Check every public IP address against TOR relays
    if bool(ips) and args.checkTor.upper() == 'Y':
        Log('Checking public addresses against TOR')
        CheckIpsAgainstTor(ips, totalPublic)

    ## Check every public IP address against a REST endpoint for location data
    if bool(ips) and args.checkLocations.upper() == 'Y':
        Log(f'Checking public addresses against {args.locationEndpoint}')
        RequestInfoFromRestEndpoint(ips, args.locationEndpoint, totalPublic)

    ## Write all IP addresses info to the output CSV file
    WriteDictToCSV(args.outputFilesName + '.csv', ips)

    # Write all IP addresses info to the output JSON file
    with open(args.outputFilesName + '.json', 'wt', encoding='utf-8') as jsonFile:
        pprint(ips, stream=jsonFile)

    if bool(ips) and args.checkLocations.upper() == 'Y':
        WriteIpsKml(ips, args.outputFilesName + '.kml')

    Log(f'DONE.\n\tIP index file: {args.outputFilesName}_index.csv\n\tIP detail results: {args.outputFilesName}.csv\n\tJSON file: {args.outputFilesName}.json\n\tKML file: {args.outputFilesName}.kml')
# end main

## Call main() at program start
if __name__ == "__main__":
    main()
