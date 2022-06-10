Download and install dependencies: 
> pip install -r requirements.txt

Generate an independent executable file (no need to have Python installed afterwards):
> pip install -r pyinstaller
> pyinstaller -wF osips.py

Display the tool help:
> python osips.py -h

Run the tool interactively:
> python osips.py

Run the tool non-interactively:
> python osips.py --checkTor Y --checkWhoIs Y --checkLocations Y --inputFolder testFolder --inputFilesPattern * --outputFilesName test
