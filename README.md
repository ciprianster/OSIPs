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
