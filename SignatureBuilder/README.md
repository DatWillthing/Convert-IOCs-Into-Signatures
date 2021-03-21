#This entire folder must be copied to effectively use the SignatureScript.ps1 stored inside.

#Copy the SignatureBuilder directory and all of its dependencies to your desktop or working directory.


##Operation of the Script
<i>You have two options of how to use the script...</i>
<ol>
    <li>Through the GUI, open up the SignatureBuilder directory.</li>
    <li>Right Click the Script and click "Run as Powershell"</li>
    <li><b>Read the errors!</b> If there is an error with the execution policy, see the "Managing Execution Policy" section of this Readme.</li>
    <li>Follow the Script and input the <u>full</u> path of the signature file when requested.</li>
    <li>The results of the script should appear in the newly created Results directory within the SignatureBuilder Directory. More guidance is in the Readme file of the Results directory.</li>
<ol>

##Managing Execution Policy
Set-ExecutionPolicy unrestricted -Force
