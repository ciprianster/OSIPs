# OSIPs
This script scans every file from a given folder recursively, extracts every IPv4 and IPv6 address, filters out the public IP addresses and then queries these IPs against TOR relays, WhoIs service and Location service. It outputs 4 files: a CSV file and a JSON file with all details of the IP addresses, a CSV file containing an index of every found IP address and a KML file with all the locations gathered.

## Features
- Parses any number of files in a single run
- Can also be run for a single input file
- Extracts all unique valid IPv4 and IPv6 addresses (correctly comparing two addresses, even if they are written differently)
- Collects publicly available Who Is information for all public IP addresses
- Queries all public IP addresses against TOR relays
- Collects geographical location information for all public IP addresses
- Can be run with command line parameters in non-interactive mode for easy integration in other scripts
- Can be run without parameters and the input values can be provided interactively
- Allows user to select what steps to perform or exclude
- Verbosely outputs information to console at every step that it performs
- Exports all IP addresses details in both a CSV file and a JSON file
- Exports a KML file that can be easily loaded on top of a map
- Keeps an index of all found IP addresses in a separate CSV file for easy traceback

## Pre-requisites:
Python 3.9.x

## Installation
To install dependencies, run:

`pip install -r requirements.txt`


### Compile to executable

`pip install pyinstaller`

`pyinstaller --onefile osips.py`


## Usage
`python osips.py [-h] [-F INPUTFOLDER] [-f INPUTFILE] [-p INPUTFILESPATTERN] [-o OUTPUTFILESNAME] [-t {y,n,Y,N}] [-w {y,n,Y,N}] [-l {y,n,Y,N}] [-locationEndpoint LOCATIONENDPOINT]`

#### Interactively
`python osips.py`

#### Non-interactively
`python osips.py --checkTor Y --checkWhoIs Y --checkLocations Y --inputFolder testFolder/ --inputFilesPattern * --outputFilesName test`

## Help
`python osips.py -h`

## Options
- `-h, --help`
		Show the help message and exit
- `-F INPUTFOLDER, --inputFolder INPUTFOLDER`
		A folder containing files with IPs (log files,  email files, text files etc). The IPs can be IPv4 and/or IPv6 and can be placed anywhere in the files. The script will parse every file in the folder and will scan for every IP
- `-f INPUTFILE, --inputFile INPUTFILE`
		Use this option to scan only one file instead of a folder with files. The file can be any text file that contains IP addresses (log files, email files, text files etc.)
- `-p INPUTFILESPATTERN, --inputFilesPattern INPUTFILESPATTERN`
		Enter the pattern to use for the files in the input folder. Example: * for all files, *.txt for text files.
- `-o OUTPUTFILESNAME, --outputFilesName OUTPUTFILESNAME`
		The name for the output files, WITHOUT EXTENSION.  4 different files will be created with this name: a CSV file storing the IP details, an index file storing the IP indexes, a JSON file storing the details and a KML file storing the locations.
- `-t {y,n,Y,N}, --checkTor {y,n,Y,N}`
		Specify if you want to check every public IP address against the TOR relays IP addresses
- `-w {y,n,Y,N}, --checkWhoIs {y,n,Y,N}`
		Specify if you want to extract WhoIs information for every public IP address
- `-l {y,n,Y,N}, --checkLocations {y,n,Y,N}`
		Specify if you want to geocode every public IP address and extract location info using https://reallyfreegeoip.org
- `-locationEndpoint LOCATIONENDPOINT`
		Default REST endpoint for location is "https://reallyfreegeoip.org/json/<IP>". You can specify a diffrent end point, includding <IP> placeholder. The result must be in JSON and must include the following fields: country_name, region_code, region_name, city, zip_code, time_zone, latitude, longitude, metro_code

## Remarks
- The tool extracts IPv4 addresses only in dot decimal notation (xxx.xxx.xxx.xxx). It doesn’t extract IPv4 addresses in decimal, octal or hexadecimal notation because of the high rate of false positives.
- Depending on the number of public IP addresses found, querying the online services could take a long time. If you are dealing with a lot of IP addresses, it is recommended to first run the tool without querying any of the services and just to extract the IP addresses. After seeing the extraction result, you can calculate an estimate of the total run time of the tool if the services are queried, and eventually choose to query only one or two of the services.
- TOR relays are checked at the moment of running the tool. Because these IPs are constantly changing, this information may not be very accurate. If a date can also be identified for an IP, then it should be checked against ExoneraTor at this address: https://metrics.torproject.org/exonerator.html
- Who Is information as well as the location information is gathered live from publicly available services, so the IP addresses are sent to these services. There are downloadable databases that would allow you to collect this information locally, but these downloads are not free and would need constant updates. This tool is not built to work with local databases.
- The default service used for location gathering is https://reallyfreegeoip.org. This is a free service with no limitations, but it may not be very accurate. You can change this service with another, by using the -locationEndpoint parameter of the script. You can provide another service that takes an IP address as a parameter and returns a JSON response. Use the <IP> as a placemark for the IP address location. Examples: https://ipapi.co/<IP>/json, https://api.ipstack.com/<IP>?access_key=ACCESS_KEY, https://freeapi.robtex.com/ipquery/<IP>. Please note that some of these other REST endpoints may not return the required fields and thus will break the script’s logic. In this case, the method named RequestInfoFromRestEndpoint should be modified accordingly.
	
## Acknowledgements
- IPv6 regex -https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
- Onion Peeler: Batch Tor Lookup Program - http://az4n6.blogspot.com/2017/02/onion-peeler-batch-tor-lookup-program.html
	
	
