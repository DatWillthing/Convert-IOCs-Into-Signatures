The purpose of this script is to take IOC files as input and, using Powershell, output them into Suricata rules.

How-To
* Copy the Convert-IOCs-Into-Signatures directory and all of its dependencies to your desktop or working directory.
* You have two options of how to use the script. If one doesn't work, try the other:

IMPORTANT
* If you do not have Excel, you can only use .CSV files as input.
* Check the files you're inputting to make sure the column headers do not contain the value "Column". If they are, simply delete the top row.

GUI
    1.) Through the GUI, open up the Convert-IOCs-Into-Signatures directory.
    2.) Right Click the SignatureScript.ps1 and click the "Run as Powershell" option.
    3.) READ THE ERRORS! If there is an error with the execution policy, see the "Managing Execution Policy" section of this Readme.
    4.) Follow the Script and input the FULL path of the signature file when requested. An easier way to do this is to drag and drop the signature file into the powershell window.
    5.) The results of the script should appear in the newly created Results directory within the Convert-IOCs-Into-Signatures Directory. More guidance is in the Readme file of the Results directory.

CLI
    1.) Open up a powershell window. (Just regular powershell, not ISE)
    2.) Change directory into the Convert-IOCs-Into-Signatures directory.
    3.) Run the command:
        ./SignatureScript.ps1 <Full\Path\to\Singature\File>
        #You can drag and drop your singature file into the powershell window here and it should automatically input the full path
    4.) READ THE ERRORS! If there is an error with the execution policy, see the "Managing Execution Policy" section of this Readme.
    5.) Follow the Script and input the FULL path of the signature file when requested. An easier way to do this is to drag and drop the signature file into the powershell window.
    6.) The results of the script should appear in the newly created Results directory within the Convert-IOCs-Into-Signatures Directory. More guidance is in the Readme file of the Results directory.


Managing Execution Policy
* Manually run the command in your Powershell window:
  *  Set-ExecutionPolicy unrestricted -Force

* Now try the script again...
