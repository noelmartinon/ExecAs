# ExecAs
Command line utility that executes a command (plaintext or encryted) as another user account or under specified user session by temporarily installing itself as a service.

## Feature summary
- Wait option : wait for passed command to terminate and return its errorlevel
- Hide option : hide the window create by command
- RunAS option : like runas.exe but password is a parameter, no admin rights needed, no service used
- Command line parameters can be encrypted into a string using AES-CBC-128 encryption algorithm
- Multi-instance execution
- Interactif mode is using current active user session either console or remote desktop session
- Windows 7 and Windows 10 32/64bits supported

## Usage
  ```
  ExecAs.exe - Version 1.0.0
  MIT License / Copyright (C) 2018 Noël Martinon

  Use:
  ExecAs.exe [-c[rypt]] [-i[nteractive]|-e[xclusive]]|-s[ystem]] |
  [[-r[unas]] -u"UserName" -d"DomainName" -p"Password"] | [-a"AppID"] [-w[ait]] [-h[ide]] Command | Encrypted_Parameters

  -c           encrypt the arguments into an 'Encrypted_Parameters' string copied
               to clipboard that can be passed as single command parameter
  -n           hide the console window associated with ExecAs.exe (NOT
               AVAILABLE WITH '-c' PARAMETER). Useful in a shortcut;)
  -i           process will be launched under credentials of the
               \"Interactive User\" if it exists otherwise as local system
  -e           process will be launched under credentials of the
               \"Interactive User\" ONLY if it exists
  -a           process will be launched under credentials of the user
               specified in \"RunAs\" parameter of AppID
  -s           process will be launched as local system
  -u -d -p     process will be launched on the result token session of the
               authenticated user according to userName,domainName,password
  -r -u -d -p  process will be launched as RUNAS command in the current
               session according to userName,domainName,password
  -w           wait option for Command to terminate
  -h           hide window option created by launched process (THIS IS NOT
               AVAILABLE WITH '-s' PARAMETER)
  Command must begin with the process (path to the exe file) to launch
  Either (-s) or (-i) or (-e) or (-a) or (-u -d -p) or (-r -u -d -p) with optional (-c)(-w)(-h) parameters or single 'Encrypted_Parameters' must supplied

  Only (-c) and (-r) parameters do not need admin permissions to run ExecAs.exe

  If using (-c) parameter then it must be the first argument

  If using (-n) parameter then it must be the first argument or the one that follows (-c)

  Examples:
  ExecAs.exe -s prog.exe
  ExecAs.exe -i -w prog.exe arg1 arg2
  ExecAs.exe -e cmd /c "dir c: && pause"
  ExecAs.exe -c -e prog.exe arg
  ExecAs.exe NnRMNy8zTEHq0vv/csDxVZ1gsiqGUIGuppzB12K3HnfYvPue6+UcM/lLsGjRmdt0BmXfETUy5IaIVQliK1UOa74zuXwzi687
  ExecAs.exe -r -u"user1" -p"pass1" -d prog.exe arg1
  ExecAs.exe -a"{731A63AF-2990-11D1-B12E-00C04FC2F56F}" prog.exe
  ExecAs.exe -c -n -r -uadministrator -padminpasswd -ddomain -w -h wmic product where \"name like 'Java%'\" call uninstall /nointeractive
  ExecAs.exe -i -w -h ExecAs.exe -r -u"user1" -p"pass1" -d prog.exe arg1
  ```

## License
MIT License / Copyright (C) 2018 Noël Martinon

Based on Valery Pryamikov's CreateProcessAsUser utility written in 1999 which was based on Keith Brown's AsLocalSystem utility (see http://read.pudn.com/downloads178/sourcecode/windows/829566/CreateProcessAsUser.cpp__.htm)

No license or restriction was found with that source code so, unless otherwise specified by Valery Pryamikov, code and binaries are released under the MIT License.

## Warning !
/!\ NOT SECURE /!\

Since this source code is public it's easy to use the decrypt() function to get the plaintext from encrypted string and potentially retrieve a password passed as an argument !
--> So modify the 2 functions encrypt() and decrypt() to your own code to increase security (get password from workgroup, change checksum size...)

/!\ NOT SECURE /!\

## How to build
Code is in pure C++/Win32 (bcc & gcc compatible).

Binary is for windows OS only.

Under linux, build it like that :
- 32bits binary
  ```
  i686-w64-mingw32-gcc -static -Os -s -std=c++11 ExecAs.cpp -o ExecAs.exe -lstdc++ -luserenv -ladvapi32 -lwtsapi32
  ```
- 64bits binary
  ```
  x86_64-w64-mingw32-gcc -static -Os -s -std=c++11 ExecAs64.cpp -o ExecAs64.exe -lstdc++ -luserenv -ladvapi32 -lwtsapi32
  ```