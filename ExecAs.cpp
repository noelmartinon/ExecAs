/////////////////////////////////////////////////////////////
// ExecAs.cpp
//
// Command line utility that executes a command (plaintext or encryted) as another user account or
// under specified user session by temporarily installing itself as a service.
//
//
/*
  MIT License (MIT)
  Copyright © 2018 Noël Martinon

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/
//
// Based on Valery Pryamikov's CreateProcessAsUser utility written in 1999
// which was based on Keith Brown's AsLocalSystem utility
// (see http://read.pudn.com/downloads178/sourcecode/windows/829566/CreateProcessAsUser.cpp__.htm)
// No license or restriction was found with that source code so, unless otherwise
// specified by Valery Pryamikov, code and binaries are released under the MIT License.
//
// Upgraded by Noël Martinon (2018) :
//   Code in pure C++/Win32 (bcc & gcc compatible)
//   Wait option added (wait for passed command to terminate and return its errorlevel)
//   Hide option added (hide the window create by command)
//   RunAS option added (like runas.exe but password is a parameter, no admin rights needed, no service used)
//   Command line parameters can be encrypted into a string
//   Multi-instance execution (unique service name based on timestamp, 	especially necessary when using wait option)
//   Interactif mode is using current active user session either console or remote desktop session
//   Windows 7 and Windows 10 32/64bits supported (service deleted after ensure it's stopped)
//
//
// /!\ NOT SECURE /!\
// Since this source code is public it's easy to use the decrypt() function to get
// the plaintext from encrypted string and potentially retrieve a password passed as an argument !
//
// So modify the 2 functions encrypt() and decrypt() to your own code to increase security (get password from workgroup, change checksum size...)
// /!\ NOT SECURE /!\
//
//
// ExecAs.exe - Version 1.1.0
// MIT License / Copyright (C) 2018 Noël Martinon
//
// Use:
// ExecAs.exe [-c[rypt]] [-i[nteractive]|-e[xclusive]]|-s[ystem]] |
// [[-r[unas]] -u"UserName" -d"DomainName" -p"Password"] | [-a"AppID"] [-w[ait]] [-h[ide]] Command | Encrypted_Parameters
//
// -c           encrypt the arguments into an 'Encrypted_Parameters' string copied
//              to clipboard that can be passed as single command parameter
// -n           hide the console window associated with ExecAs.exe (NOT
//              AVAILABLE WITH '-c' PARAMETER). Useful in a shortcut;)
// -i           process will be launched under credentials of the
//              \"Interactive User\" if it exists otherwise as local system
// -e           process will be launched under credentials of the
//              \"Interactive User\" ONLY if it exists
// -a           process will be launched under credentials of the user
//              specified in \"RunAs\" parameter of AppID
// -s           process will be launched as local system
// -u -d -p     process will be launched on the result token session of the
//              authenticated user according to userName,domainName,password
// -r -u -d -p  process will be launched as RUNAS command in the current
//              session according to userName,domainName,password
// -w           wait option for Command to terminate
// -h           hide window option created by launched process (THIS IS NOT
//              AVAILABLE WITH '-s' PARAMETER)
// Command must begin with the process (path to the exe file) to launch
// Either (-s) or (-i) or (-e) or (-a) or (-u -d -p) or (-r -u -d -p) with optional (-c)(-w)(-h) parameters or single 'Encrypted_Parameters' must supplied
//
// Only (-c) and (-r) parameters do not need admin permissions to run ExecAs.exe
//
// If using (-c) parameter then it must be the first argument
//
// If using (-n) parameter then it must be the first argument or the one that follows (-c)
//
// 'Encrypted_Parameters' can be a path to a text file that strickly contains the encrypted command
//
// Examples:
// ExecAs.exe -s prog.exe
// ExecAs.exe -i -w prog.exe arg1 arg2
// ExecAs.exe -e cmd /c "dir c: && pause"
// ExecAs.exe -c -e prog.exe arg
// ExecAs.exe NnRMNy8zTEHq0vv/csDxVZ1gsiqGUIGuppzB12K3HnfYvPue6+UcM/lLsGjRmdt0BmXfETUy5IaIVQliK1UOa74zuXwzi687
// ExecAs.exe encrypted_cmd.txt
// ExecAs.exe -r -u"user1" -p"pass1" -d prog.exe arg1
// ExecAs.exe -a"{731A63AF-2990-11D1-B12E-00C04FC2F56F}" prog.exe
// ExecAs.exe -c -n -r -uadministrator -padminpasswd -ddomain -w -h wmic product where \"name like 'Java%'\" call uninstall /nointeractive
// ExecAs.exe -i -w -h ExecAs.exe -r -u"user1" -p"pass1" -d prog.exe arg1
//
//
/////////////////////////////////////////////////////////////
#define APP_VERSION "1.1.0"

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <userenv.h>
#include <ntsecapi.h>
#include <wtsapi32.h>
#include <ntstatus.h>
#include "common.hpp"

#include "Base64.hpp"
#include "Rijndael.hpp"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")

#define E_OBJ_IS_A_SERVICE          0x80040500 //-2147220224
#define E_NO_RUN_AS_DATA            0x80040501 //-2147220223
#define E_RUN_AS_INTERACTIVE        0x80040502 //-2147220222
#define E_NO_INTERACTIVE_SESSION    0x80040503 //-2147220221
#define E_SHELL_NOT_FOUND           0x80040504 //-2147220220  0x80040504(hex) = 2147747076(dec)
                                               // => dword to int (returned value) : 2147747076 - 2^32 = -2147220220
#define GUIDSTR_MAX         38
#define MAX_TASKS           256
#define MAX_CMD_LEN         8192

#define SERVICE_NAME        "ProcessAU" // Process As User

// Encryption used is AES-128-CBC :
// - For CBC mode, the initialization vector (IV) is the size of a block, which for AES is 16 bytes (128 bits)
// - The key size is 16 bytes (128 bits) for AES-128-CBC
#define BLOCK_SIZE  16
#define IV_SIZE     16
#define KEY_SIZE    16

#define CHECK_SIZE 8

int argc_dynamic = 0;
char **argv_dynamic = NULL;

LPCTSTR g_servicename;
SERVICE_STATUS_HANDLE g_hss;
SERVICE_STATUS g_ss;

void DeleteDynamic();
HRESULT GrantDesktopAccess(HANDLE hToken);

//---------------------------------------------------------------------------
HRESULT GetProcessToken(DWORD dwProcessID, LPHANDLE token, DWORD nUserNameMax, LPSTR szUserName, DWORD nUserDomainMax, LPSTR szUserDomain)
{
    HANDLE hProcess=OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION,TRUE,dwProcessID);
    HRESULT retval = S_OK;
    if(hProcess) {
        HANDLE hToken = INVALID_HANDLE_VALUE;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) retval = HRESULT_FROM_WIN32(GetLastError());
        else {
            BYTE buf[MAX_PATH]; DWORD dwRead = 0;
            if (!GetTokenInformation(hToken, TokenUser, buf, MAX_PATH, &dwRead)) retval = HRESULT_FROM_WIN32(GetLastError());
            else {
                TOKEN_USER *puser = reinterpret_cast<TOKEN_USER*>(buf);
                SID_NAME_USE eUse;
                if (!LookupAccountSid(NULL, puser->User.Sid, szUserName, &nUserNameMax, szUserDomain, &nUserDomainMax, &eUse))
                    retval = HRESULT_FROM_WIN32(GetLastError());
            }
            if (FAILED(retval)) return retval;
            if (!DuplicateTokenEx(hToken,
                TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE,
                NULL, SecurityImpersonation, TokenPrimary,token))
                retval = HRESULT_FROM_WIN32(GetLastError());
            else  retval = S_OK;
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    } else retval = HRESULT_FROM_WIN32(GetLastError());
    return retval;
}
//---------------------------------------------------------------------------
DWORD GetCurrentUserSessionId_RemoteDesktop()
{
    int dwSessionId = 0;

    PWTS_SESSION_INFO pSessionInfo = 0;
    DWORD dwCount = 0;

    // Get the list of all terminal sessions 
    WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                         &pSessionInfo, &dwCount);

    // look over obtained list in search of the active session
    for (DWORD i = 0; i < dwCount; ++i)
    {
        WTS_SESSION_INFO si = pSessionInfo[i];
        if (WTSActive == si.State)
        { 
            // If the current session is active – store its ID
            dwSessionId = si.SessionId;
            break;
        }
    } 	
	
	WTSFreeMemory(pSessionInfo);

    return dwSessionId;
}
//---------------------------------------------------------------------------
HRESULT GetInteractiveUserToken(LPHANDLE token, DWORD nUserNameMax, LPSTR szUserName, DWORD nUserDomainMax, LPSTR szUserDomain)
{
    DWORD session_id = WTSGetActiveConsoleSessionId();
	DWORD explorer_pid = 0xFFFFFFFF;
	DWORD rdp_session_id = GetCurrentUserSessionId_RemoteDesktop();
	bool bShellFound = false;

	PROCESSENTRY32 proc_entry = { 0 };
	HANDLE snap = INVALID_HANDLE_VALUE;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());
    
    proc_entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snap, &proc_entry))
        return HRESULT_FROM_WIN32(GetLastError());

    do
    {
        if (stricmp(proc_entry.szExeFile, "explorer.exe") == 0)
        {
            // winlogon process found...make sure it's running in the console session
            DWORD explorer_session_id = 0;
            bShellFound = true;
  
            if (ProcessIdToSessionId(proc_entry.th32ProcessID, &explorer_session_id) &&
                (explorer_session_id == session_id || explorer_session_id == rdp_session_id))
            {
                explorer_pid = proc_entry.th32ProcessID;
                break;
            }
        }
    } while (Process32Next(snap, &proc_entry));

    CloseHandle(snap);
  
    if (!bShellFound)
        return E_SHELL_NOT_FOUND;

    if (0xFFFFFFFF == explorer_pid)
        return E_NO_INTERACTIVE_SESSION;
  
    return GetProcessToken(explorer_pid, token, nUserNameMax, szUserName, nUserDomainMax, szUserDomain);
}
//---------------------------------------------------------------------------
HRESULT GetRunAsPassword (LPSTR AppID, int nPasswordMax, LPSTR szPassword, int nUserNameMax, LPSTR szUserName, int nUserDomainMax, LPSTR szUserDomain)
{
    LSA_OBJECT_ATTRIBUTES objectAttributes;
    HANDLE                policyHandle = NULL;
    LSA_UNICODE_STRING    lsaKeyString;
    PLSA_UNICODE_STRING   lsaPasswordString;
    char                  key [4 + GUIDSTR_MAX + 1];
    ULONG                 returnValue;
    char                  keyName [MAX_PATH+1];
    HKEY                  registryKey;

    sprintf (keyName, "AppID\\%s", AppID);
    returnValue = RegOpenKeyEx (HKEY_CLASSES_ROOT, keyName, 0, KEY_READ, &registryKey);
    if (returnValue == ERROR_SUCCESS) {
        DWORD valueType;
        DWORD valueSize = 0;
        returnValue = RegQueryValueEx (registryKey, "LocalService", NULL, &valueType, NULL, &valueSize);

        if (returnValue == ERROR_SUCCESS || returnValue == ERROR_MORE_DATA) return RegCloseKey (registryKey), E_OBJ_IS_A_SERVICE;

        char principal[MAX_PATH+1];
        valueSize = (MAX_PATH+1)*sizeof(CHAR);
        returnValue = RegQueryValueEx(registryKey, "RunAs", NULL, &valueType, (BYTE*)principal, &valueSize);
        RegCloseKey (registryKey);
        if (returnValue != ERROR_SUCCESS) return E_NO_RUN_AS_DATA;
        if (stricmp(principal, "Interactive User") == 0) return E_RUN_AS_INTERACTIVE;
        char *ptmp = strchr(principal, '\\');
        if (ptmp == 0) {
            memset(szUserDomain, 0, nUserDomainMax);
            strncpy(szUserName, principal, nUserNameMax);
        } else {
            memset(szUserDomain, 0, nUserDomainMax);
            strncpy(szUserDomain, principal, min(nUserDomainMax, ptmp-principal));
            strncpy(szUserName, ptmp+1, nUserNameMax);
        }
    } else return E_NO_RUN_AS_DATA;

    strcpy (key, "SCM:");
    strcat (key, AppID);
    
    const size_t cSize = strlen(key)+1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs (wc, key, cSize);

    lsaKeyString.Length = (USHORT) ((strlen (key) + 1) * sizeof (CHAR));
    lsaKeyString.MaximumLength = (GUIDSTR_MAX + 5) * sizeof (CHAR);
    lsaKeyString.Buffer = wc;

    //
    // Open the local security policy
    //
    memset (&objectAttributes, 0x00, sizeof (LSA_OBJECT_ATTRIBUTES));
    objectAttributes.Length = sizeof (LSA_OBJECT_ATTRIBUTES);

    returnValue = LsaOpenPolicy (NULL,
                                 &objectAttributes,
                                 POLICY_GET_PRIVATE_INFORMATION,
                                 &policyHandle);

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    //
    // Read the user's password
    //
    returnValue = LsaRetrievePrivateData (policyHandle,
                                          &lsaKeyString,
                                          &lsaPasswordString);

    if (returnValue != ERROR_SUCCESS)
    {
        LsaClose (policyHandle);
        return returnValue;
    }

    const size_t cwSize = wcslen(lsaPasswordString->Buffer)+1;
    char *str_lsaPasswordString_Buffer = new char[cwSize];
    wcstombs(str_lsaPasswordString_Buffer, lsaPasswordString->Buffer, cwSize);

    LsaClose (policyHandle);
    strncpy (szPassword, str_lsaPasswordString_Buffer, nPasswordMax);
    LsaFreeMemory(lsaPasswordString->Buffer);

    return ERROR_SUCCESS;
}
//---------------------------------------------------------------------------
void Quit( const char *pszMsg, int nExitCode = 1 )
{
    DeleteDynamic();
    if (pszMsg) {
        CharToOem((LPCSTR)pszMsg, (LPSTR)pszMsg);
        printf ( "%s\n", pszMsg );
    }
    exit( nExitCode );
}
//---------------------------------------------------------------------------
void DisplayError(LPCSTR pszMsg=NULL, DWORD dwExitCode = GetLastError())
{
    LPVOID lpMsgBuf;
    //if ( dwExitCode==0xC000013A) dwExitCode=1; // the application has been terminated by closing command prompt window
    //if ( dwExitCode==0xFF) dwExitCode=1; // the application has been terminated by user's keyboard input CTRL+C or CTRL+Break
    DWORD IsFormatted = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwExitCode,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL );
    if (IsFormatted) {
        CharToOem((LPCSTR)lpMsgBuf, (LPSTR)lpMsgBuf);
        if (pszMsg && dwExitCode>1) printf( "%s - Err %lu: %s", pszMsg, dwExitCode, (LPCTSTR)lpMsgBuf );
        else if (dwExitCode>1) printf ( "Err %lu: %s", dwExitCode, (LPCTSTR)lpMsgBuf );
        else printf ( "%s", (LPCTSTR)lpMsgBuf );
        LocalFree( lpMsgBuf );
    }
    else if (pszMsg && dwExitCode>0) printf( "%s - Err %lu\n", pszMsg, dwExitCode );
    else if (dwExitCode>0) printf( "Err %lu\n", dwExitCode ); 

    Quit( NULL, dwExitCode);
}
//---------------------------------------------------------------------------
void PrintUsageAndQuit()
{
    Quit( "ExecAs.exe - Version "
          APP_VERSION
          "\nMIT License / Copyright (C) 2018 Noël Martinon\n\n"
          "Use:\n"
          "ExecAs.exe [-c[rypt]] [-n[oconsole]] [-i[nteractive]|-e[xclusive]]|-s[ystem]] | "
          "[[-r[unas]] -u\"UserName\" -d\"DomainName\" -p\"Password\"] | [-a\"AppID\"] [-w[ait]] [-h[ide]] Command | Encrypted_Parameters\n\n"
          "-c           encrypt the arguments into an 'Encrypted_Parameters' string copied\n"
          "             to clipboard that can be passed as single command parameter\n"
          "-n           hide the console window associated with ExecAs.exe (NOT\n"
          "             AVAILABLE WITH '-c' PARAMETER). Useful in a shortcut;)\n"
          "-i           process will be launched under credentials of the\n"
          "             \"Interactive User\" if it exists otherwise as local system\n"
          "-e           process will be launched under credentials of the\n"
          "             \"Interactive User\" ONLY if it exists\n"
          "-a           process will be launched under credentials of the user\n"
          "             specified in \"RunAs\" parameter of AppID\n"
          "-s           process will be launched as local system\n"
          "-u -d -p     process will be launched on the result token session of the\n"
          "             authenticated user according to userName,domainName,password\n"
          "-r -u -d -p  process will be launched as RUNAS command in the current\n"
          "             session according to userName,domainName,password\n"
          "-w           wait option for Command to terminate\n"
          "-h           hide window option created by launched process (NOT AVAILABLE\n"
          "             WITH '-s' PARAMETER)\n"
          "Command must begin with the process (path to the exe file) to launch\n"
          "\nEither (-s) or (-i) or (-e) or (-a) or (-u -d -p) or (-r -u -d -p) with optional (-c)(-w)(-h) parameters or single 'Encrypted_Parameters' must supplied\n"
          "\nOnly (-c) and (-r) parameters do not need admin permissions to run ExecAs.exe\n"
          "\nIf using (-c) parameter then it must be the first argument\n"
          "\nIf using (-n) parameter then it must be the first argument or the one that follows (-c)\n"
          "\n'Encrypted_Parameters' can be a path to a text file that strickly contains the encrypted command\n"
          "\nExamples:\n"
          "ExecAs.exe -s prog.exe\n"
          "ExecAs.exe -i -w prog.exe arg1 arg2\n"
          "ExecAs.exe -e cmd /c \"dir c: && pause\"\n"
          "ExecAs.exe -c -e prog.exe arg\n"
          "ExecAs.exe NnRMNy8zTEHq0vv/csDxVZ1gsiqGUIGuppzB12K3HnfYvPue6+UcM/lLsGjRmdt0BmXfETUy5IaIVQliK1UOa74zuXwzi687\n"
          "ExecAs.exe encrypted_cmd.txt\n"
          "ExecAs.exe -r -u\"user1\" -p\"pass1\" -d prog.exe arg1\n"
          "ExecAs.exe -a\"{731A63AF-2990-11D1-B12E-00C04FC2F56F}\" prog.exe\n"
          "ExecAs.exe -c -n -r -uadministrator -padminpasswd -ddomain -w -h wmic product where \\\"name like 'Java%'\\\" call uninstall /nointeractive");
}
//---------------------------------------------------------------------------
void* GetAdminSid()
{
    SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;
    void* psid = 0;
    if ( !AllocateAndInitializeSid( &ntauth, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &psid ) )
        DisplayError( "AllocateAndInitializeSid" );
    return psid;
}
//---------------------------------------------------------------------------
void* GetLocalSystemSid()
{
    SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;
    void* psid = 0;
    if ( !AllocateAndInitializeSid( &ntauth, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &psid ) )
        DisplayError( "AllocateAndInitializeSid" );
    return psid;
}
//---------------------------------------------------------------------------
bool IsAdmin()
{
    bool bIsAdmin = false;
    HANDLE htok = 0;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &htok ) )
        DisplayError( "OpenProcessToken" );

    DWORD cb = 0;
    GetTokenInformation( htok, TokenGroups, 0, 0, &cb );
    TOKEN_GROUPS* ptg = (TOKEN_GROUPS*)malloc( cb );
    if ( !ptg )
        DisplayError( "malloc" );
    if ( !GetTokenInformation( htok, TokenGroups, ptg, cb, &cb ) )
        DisplayError( "GetTokenInformation" );

    void* pAdminSid = GetAdminSid();

    SID_AND_ATTRIBUTES* const end = ptg->Groups + ptg->GroupCount;
    SID_AND_ATTRIBUTES* it;
    for ( it = ptg->Groups; end != it; ++it )
        if ( EqualSid( it->Sid, pAdminSid ) )
            break;

    bIsAdmin = end != it;

    FreeSid( pAdminSid );
    free( ptg );
    CloseHandle( htok );

    return bIsAdmin;
}
//---------------------------------------------------------------------------
bool IsLocalSystem()
{
    bool bIsLocalSystem = false;
    HANDLE htok = 0;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &htok ) )
        DisplayError( "OpenProcessToken" );

    BYTE userSid[256];
    DWORD cb = sizeof userSid;
    if ( !GetTokenInformation( htok, TokenUser, userSid, cb, &cb ) )
        DisplayError( "GetTokenInformation" );
    TOKEN_USER* ptu = (TOKEN_USER*)userSid;

    void* pLocalSystemSid = GetLocalSystemSid();

    bIsLocalSystem = EqualSid( pLocalSystemSid, ptu->User.Sid ) ? true : false;

    FreeSid( pLocalSystemSid );
    CloseHandle( htok );

    return bIsLocalSystem;
}
//---------------------------------------------------------------------------
void StartAsService( int argc, const char *argv[] )
{
    char szModuleFileName[MAX_PATH];
    GetModuleFileName( 0, szModuleFileName, sizeof szModuleFileName / sizeof *szModuleFileName );
    
    // come up with unique name for this service
    SC_HANDLE hscm = OpenSCManager( 0, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE );
    if ( !hscm )
        DisplayError( "OpenSCManager" );

    SC_HANDLE hsvc = 0;
    for ( int nRetry = 0; nRetry < 2; ++nRetry )
    {
        hsvc = CreateService(   hscm,
                                g_servicename,
                                g_servicename,
                                SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
                                SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                                SERVICE_DEMAND_START,
                                SERVICE_ERROR_NORMAL,
                                szModuleFileName,
                                0, 0,
                                0,
                                0, 0 );
        if ( hsvc )
            break;
        else if ( ERROR_SERVICE_EXISTS == GetLastError() )
        {
            SC_HANDLE hsvc = OpenService( hscm, g_servicename, DELETE );
            DeleteService( hsvc );
            CloseServiceHandle( hsvc );
            hsvc = 0;
        }
        else break;
    }

    if ( !hsvc )
        DisplayError( "CreateService" );

    if ( !StartService( hsvc, argc, argv ) ) {
        DeleteService( hsvc );
        CloseServiceHandle( hsvc );
        CloseServiceHandle( hscm );
        DisplayError( "StartService" );
    }
                             
    SERVICE_STATUS _ss;
    do {
      QueryServiceStatus (hsvc, &_ss);
      Sleep(100);
    }
    while ( _ss.dwCurrentState != SERVICE_STOPPED );

    DeleteService( hsvc );
    CloseServiceHandle( hsvc );
    CloseServiceHandle( hscm );
}
//---------------------------------------------------------------------------
void WINAPI Handler( DWORD )
{
    SetServiceStatus( g_hss, &g_ss );
}
//---------------------------------------------------------------------------
void WINAPI ServiceMain( DWORD argc, char *argv[] )
{
    char szCurrentDirectory[MAX_PATH];
    GetModuleFileName( 0, szCurrentDirectory, sizeof szCurrentDirectory / sizeof *szCurrentDirectory );
    char *pc=strrchr(szCurrentDirectory,'\\');
    *pc = '\0';

    g_servicename = argv[argc-1];
    g_ss.dwCurrentState = SERVICE_RUNNING;
    g_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;

    g_hss = RegisterServiceCtrlHandler( g_servicename, Handler );
    SetServiceStatus( g_hss, &g_ss );
    bool fAsSystem = false;
    bool fAsAppID = false;
    bool fAsInteractive = false;
    bool fRunWithoutSession = false;
    bool fEqualToInteractive = false;
    bool fWaitToTerminate = false;
    bool fShowWindow = true;

    for (int i = 1; i < argc && i <=2; i++) {
        if (strnicmp(argv[i], "-s", 2)==0) fAsSystem = true;
        else if (strnicmp(argv[i], "-w", 2)==0) fWaitToTerminate = true;
        else break;
    }

    DWORD dwExitCode = 0;
    HANDLE hptoken = INVALID_HANDLE_VALUE;
    DWORD dwErr = 0;
    LPCSTR szDescr = NULL;
    do {
        if (!fAsSystem) {
            LPSTR szcUser = NULL;
            LPSTR szcDomain = NULL;
            LPSTR szcPassword = NULL;
            LPSTR szcAppID = NULL;
            char szPassword[MAX_PATH], szUserName[MAX_PATH], szUserDomain[MAX_PATH];
            memset(szPassword,0,sizeof(szPassword));
            memset(szUserName,0,sizeof(szUserName));
            memset(szUserDomain,0,sizeof(szUserDomain));
            for (DWORD i = 1; i < argc; i++) {
                if (strnicmp(argv[i], "-d",2)==0) szcDomain = argv[i]+2;
                else if (strnicmp(argv[i], "-u", 2)==0) szcUser = argv[i]+2;
                else if (strnicmp(argv[i], "-p", 2)==0) szcPassword = argv[i]+2;
                else if (strnicmp(argv[i], "-a", 2)==0) szcAppID = argv[i]+2;
                else if (strnicmp(argv[i], "-i", 2)==0) {fAsInteractive = true; fRunWithoutSession = true;}
                else if (strnicmp(argv[i], "-e", 2)==0) fAsInteractive = true;
                else if (strnicmp(argv[i], "-w", 2)==0) fWaitToTerminate = true;
                else if (strnicmp(argv[i], "-h", 2)==0) fShowWindow = false;
                else break;
            }
            if (szcAppID) {
                fAsAppID = true;
                if (FAILED(dwErr = GetRunAsPassword(szcAppID, MAX_PATH, szPassword, MAX_PATH, szUserName, MAX_PATH, szUserDomain))) {
                    if (E_RUN_AS_INTERACTIVE == dwErr) {
                        fAsAppID = false;
                        fAsInteractive = true;
                    } else {szDescr = "Failed to retrieve AppID data"; break;}
                } else {
                    szcUser = szUserName;
                    szcDomain = szUserDomain;
                    szcPassword = szPassword;
                }
            }
            if (!fAsInteractive && !fAsAppID) {
                strcpy(szUserName,szcUser);
                strcpy(szUserDomain, szcDomain);
                strcpy(szPassword, szcPassword);
            }
            if (fAsInteractive) {
                if (FAILED(dwErr = GetInteractiveUserToken(&hptoken, MAX_PATH, szUserName, MAX_PATH, szUserDomain))) {
                    if (fRunWithoutSession) {
                        dwErr = 0;
                    } else { szDescr = "Failed to retrieve interactive session"; break; }
                }
            } else {
                if (!LogonUser(szcUser,szcDomain,szcPassword, 
                    LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hptoken)) {
                    dwErr = GetLastError(), szDescr = "LogonUser failed"; break; }
                HANDLE htmp;
                memset(szPassword, 0, sizeof(szPassword));
                szcUser = szPassword;
                szcDomain = szPassword + MAX_PATH/2;
                if (FAILED(dwErr = GetInteractiveUserToken(&htmp, MAX_PATH/2, szcUser, MAX_PATH/2, szcDomain))) {
                    szDescr = "Failed to retrieve interactive session"; break;}
                CloseHandle(htmp);
                fEqualToInteractive = (stricmp(szcUser, szUserName) == 0 && stricmp(szcDomain, szUserDomain) == 0);
            }
        }

        char cmd[MAX_CMD_LEN];
        char *dst = cmd;
        char *dstEnd = cmd + sizeof cmd / sizeof *cmd;
        char **it = argv + ((fAsSystem ||fAsAppID||fAsInteractive)?2:7) + ((fWaitToTerminate)?1:0) + ((fShowWindow)?0:1);
        char **const end = argv + argc -1; // -1 because last argv (service_name) is ignored
        while ( end != it )
        {
            // add whitespace between args
            if ( dst != cmd )
                *dst++ = ' ';

            // watch for overflow
            const int cch = lstrlen( *it );
            if ( dst + cch + 2 > dstEnd )
                break;

            // concatenate args
            lstrcpy( dst, *it );
            dst += cch;
            ++it;
        }
        *dst = '\0';

        STARTUPINFO si;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        memset(&pi, 0, sizeof(pi));
        
        if (!fAsInteractive && !fEqualToInteractive && !fAsSystem && hptoken!=INVALID_HANDLE_VALUE && (dwErr = GrantDesktopAccess(hptoken))!=S_OK)
                szDescr = "GrantDesktopAccess failed";

        // Get all necessary environment variables of logged in user
        // to pass them to the process (only used by console application)
        char* lpEnvironment = NULL;
        DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
        if (CreateEnvironmentBlock((void**)&lpEnvironment, hptoken, TRUE))
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;

        if (!fShowWindow)
        {
            dwCreationFlags |= CREATE_NO_WINDOW;
            si.dwFlags |= STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
        }

        if (INVALID_HANDLE_VALUE != hptoken) {
            if ( CreateProcessAsUser(hptoken, 0, cmd, 0, 0, FALSE, dwCreationFlags, lpEnvironment, szCurrentDirectory, &si, &pi ) ) {
                if (fWaitToTerminate) {
                    WaitForSingleObject( pi.hProcess, INFINITE );
                    GetExitCodeProcess( pi.hProcess, &dwExitCode );
                }
                CloseHandle( pi.hThread );
                CloseHandle( pi.hProcess );
            } else dwErr = GetLastError(), szDescr = "CreateProcessAsUser failed";
            hptoken = (CloseHandle(hptoken), INVALID_HANDLE_VALUE);
        } else if ( CreateProcess( 0, cmd, 0, 0, FALSE, 0, 0, szCurrentDirectory, &si, &pi ) ) {
            if (fWaitToTerminate) {
                WaitForSingleObject( pi.hProcess, INFINITE );
                GetExitCodeProcess( pi.hProcess, &dwExitCode );
            }
            CloseHandle( pi.hThread );
            CloseHandle( pi.hProcess );
        } else dwErr = GetLastError(), szDescr = "CreateProcess failed";

        if (lpEnvironment != NULL) DestroyEnvironmentBlock(lpEnvironment);
    } while(false);

    char sFileMap[MAX_PATH];
    sprintf(sFileMap, "Global\\filemap_%s", g_servicename);
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE,0,PAGE_READWRITE,0,0x4000,sFileMap);
    int* mData = (int*)MapViewOfFile(hFileMap,FILE_MAP_ALL_ACCESS,0,0,0);
    *mData = dwExitCode;
    if ( dwExitCode==0 && dwErr ) *mData = dwErr;
    UnmapViewOfFile(mData);
    CloseHandle(hFileMap);

    if (dwErr) {
        HANDLE h;
        if (hptoken != INVALID_HANDLE_VALUE) hptoken = (CloseHandle(hptoken), INVALID_HANDLE_VALUE);
        h = RegisterEventSource(NULL, SERVICE_NAME);

        LPSTR lpszStrings[1];
        char szErrMsg[512];
        char szMsg[1024];
        if ( FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM, 0, dwErr, 0, szErrMsg, sizeof szErrMsg / sizeof *szErrMsg, 0 ))
            sprintf ( szMsg, "%s : %s", szDescr, szErrMsg );
        else sprintf ( szMsg, "%s", szDescr);
        lpszStrings[0] = szMsg;

        if (h != NULL)  {
            ReportEvent(h, EVENTLOG_ERROR_TYPE, 0, dwErr, NULL, (szDescr)?1:0, 0, (szDescr)?(LPCSTR*)&lpszStrings[0]:NULL,NULL);
            DeregisterEventSource(h);
        }
    }
    g_ss.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus( g_hss, &g_ss );
}
//---------------------------------------------------------------------------
HRESULT RetrieveLogonSid(HANDLE hToken,PSID *pLogonSid)
{
    PTOKEN_GROUPS   ptgGroups = NULL;
    DWORD           cbBuffer  = 0;
    DWORD           dwSidLength;
    UINT            i;
    HRESULT         hr=S_OK;

    try {
        *pLogonSid = NULL;

        GetTokenInformation(hToken, TokenGroups, ptgGroups, cbBuffer, &cbBuffer);
        if (cbBuffer && !(ptgGroups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer))) { hr = E_OUTOFMEMORY; goto return_RetrieveLogonSid; }
        if (!GetTokenInformation(hToken,TokenGroups,ptgGroups,cbBuffer,&cbBuffer)) { hr = GetLastError(); goto return_RetrieveLogonSid; }
        
        // Get the logon Sid by looping through the Sids in the token
        for(i = 0 ; i < ptgGroups->GroupCount ; i++) {
            if (ptgGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
                if (!IsValidSid(ptgGroups->Groups[i].Sid)) { hr = E_FAIL; goto return_RetrieveLogonSid; }
                dwSidLength=GetLengthSid(ptgGroups->Groups[i].Sid);
    
                if((*pLogonSid = (PSID)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSidLength)) == NULL) { hr = E_OUTOFMEMORY; goto return_RetrieveLogonSid; }
                if (!CopySid(dwSidLength,*pLogonSid,ptgGroups->Groups[i].Sid)) { hr = GetLastError(); goto return_RetrieveLogonSid; }
                hr = S_OK;
                goto return_RetrieveLogonSid;
            }
        }
        hr = E_INVALIDARG;

        return_RetrieveLogonSid:
        if (hr != S_OK) {
            if(*pLogonSid != NULL) {
                HeapFree(GetProcessHeap(), 0, *pLogonSid);
                *pLogonSid = NULL;
            }
        }
        if (ptgGroups != NULL) HeapFree(GetProcessHeap(), 0, ptgGroups);
        return hr;

    } catch(...){
        if (hr != S_OK) {
            if(*pLogonSid != NULL) {
                HeapFree(GetProcessHeap(), 0, *pLogonSid);
                *pLogonSid = NULL;
            }
        }
        if (ptgGroups != NULL) HeapFree(GetProcessHeap(), 0, ptgGroups);
    }
    return E_UNEXPECTED;
}
//---------------------------------------------------------------------------
HRESULT InsertSidInAcl(PSID pSid,PACL pAclSource,PACL *pAclDestination,DWORD AccessMask,bool bAddSid,bool bFreeOldAcl)
{
    ACL_SIZE_INFORMATION    AclInfo;
    DWORD                   dwNewAclSize;
    LPVOID                  pAce;
    DWORD                   AceCounter;
    HRESULT                 hr=S_OK;

    try {
        if (pAclSource == NULL) {
            *pAclDestination = NULL;
            return S_OK;
        }

        if (!IsValidSid(pSid)) { hr = E_FAIL; goto return_InsertSidInAcl; }

        if (!GetAclInformation(pAclSource,&AclInfo,sizeof(ACL_SIZE_INFORMATION),AclSizeInformation)) { hr = GetLastError(); goto return_InsertSidInAcl; }

        //  Compute size for new ACL, based on addition or subtraction of ACE
        if (bAddSid) dwNewAclSize = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD);
        else dwNewAclSize = AclInfo.AclBytesInUse - sizeof(ACCESS_ALLOWED_ACE) - GetLengthSid(pSid) + sizeof(DWORD);

        *pAclDestination = (PACL) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
        if (*pAclDestination == NULL) { hr = E_OUTOFMEMORY; goto return_InsertSidInAcl; }

        if (!InitializeAcl(*pAclDestination, dwNewAclSize, ACL_REVISION)) { hr = GetLastError(); goto return_InsertSidInAcl; }

        // copy existing ACEs to new ACL
        for(AceCounter = 0 ; AceCounter < AclInfo.AceCount ; AceCounter++) {
            if (!GetAce(pAclSource, AceCounter, &pAce)) { hr = GetLastError(); goto return_InsertSidInAcl; }
            if (!bAddSid) {
                // we only care about ACCESS_ALLOWED ACEs
                if ((((PACE_HEADER)pAce)->AceType) == ACCESS_ALLOWED_ACE_TYPE) {
                    PSID pTempSid=(PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart;
                    if (EqualSid(pSid, pTempSid)) continue;
                }
            }

            if (!AddAce(*pAclDestination,ACL_REVISION,0,pAce,((PACE_HEADER)pAce)->AceSize)) { hr = GetLastError(); goto return_InsertSidInAcl; }
        }

        if (bAddSid && !AddAccessAllowedAce(*pAclDestination,ACL_REVISION,AccessMask,pSid)) { hr = GetLastError(); goto return_InsertSidInAcl; }
        hr = S_OK;

        return_InsertSidInAcl:
        if (hr != S_OK) {
            if(*pAclDestination != NULL) HeapFree(GetProcessHeap(), 0, *pAclDestination);
        } else if (bFreeOldAcl) HeapFree(GetProcessHeap(), 0, pAclSource);
        return hr;

    } catch(...){
        if (hr != S_OK) {
            if(*pAclDestination != NULL) HeapFree(GetProcessHeap(), 0, *pAclDestination);
        } else if (bFreeOldAcl) HeapFree(GetProcessHeap(), 0, pAclSource);
    }
    return E_UNEXPECTED;
}
//---------------------------------------------------------------------------
HRESULT AdjustWinstaDesktopSecurity(HWINSTA hWinsta, HDESK hDesktop, PSID pLogonSid, bool bGrant, HANDLE hToken)
{
    SECURITY_INFORMATION    si = DACL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR    sdDesktop = NULL;
    PSECURITY_DESCRIPTOR    sdWinsta = NULL;
    SECURITY_DESCRIPTOR     sdNewDesktop;
    SECURITY_DESCRIPTOR     sdNewWinsta;
    DWORD                   sdDesktopLength = 0;    /* allocation size */
    DWORD                   sdWinstaLength  = 0;    /* allocation size */
    PACL                    pDesktopDacl;       /* previous Dacl on Desktop */
    PACL                    pWinstaDacl;        /* previous Dacl on Winsta */
    PACL                    pNewDesktopDacl = NULL; /* new Dacl for Desktop */
    PACL                    pNewWinstaDacl  = NULL; /* new Dacl for Winsta */
    BOOL                    bDesktopDaclPresent;
    BOOL                    bWinstaDaclPresent;
    BOOL                    bDaclDefaultDesktop;
    BOOL                    bDaclDefaultWinsta;
    HRESULT                 hr = S_OK;
    PSID                    pUserSid = NULL;

    try {
        GetUserObjectSecurity(hDesktop, &si, sdDesktop, sdDesktopLength, &sdDesktopLength);

        if (sdDesktopLength) sdDesktop = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sdDesktopLength);

        if (!GetUserObjectSecurity(hDesktop,&si,sdDesktop,sdDesktopLength,&sdDesktopLength)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        GetUserObjectSecurity(hWinsta,&si,sdWinsta,sdWinstaLength,&sdWinstaLength);

        if (sdWinstaLength) sdWinsta = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sdWinstaLength);

        if (!GetUserObjectSecurity(hWinsta,&si,sdWinsta,sdWinstaLength,&sdWinstaLength)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        if (!GetSecurityDescriptorDacl(sdDesktop,&bDesktopDaclPresent, &pDesktopDacl, &bDaclDefaultDesktop)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        if (!GetSecurityDescriptorDacl(sdWinsta,&bWinstaDaclPresent,&pWinstaDacl,&bDaclDefaultWinsta)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        // Create new DACL with Logon and User Sid for Desktop
        if(bDesktopDaclPresent && (hr = InsertSidInAcl(pLogonSid,pDesktopDacl,&pNewDesktopDacl,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW |
                DESKTOP_CREATEMENU | DESKTOP_SWITCHDESKTOP | DESKTOP_ENUMERATE, bGrant,false)) != S_OK)  goto return_AdjustWinstaDesktopSecurity;

        // Create new DACL with Logon and User Sid for Window station
        if(bWinstaDaclPresent && (hr = InsertSidInAcl(pLogonSid,pWinstaDacl,&pNewWinstaDacl,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL
                | WINSTA_ACCESSGLOBALATOMS | WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | 
                WINSTA_ACCESSCLIPBOARD | WINSTA_ENUMERATE | WINSTA_EXITWINDOWS, bGrant, false)) != S_OK)  goto return_AdjustWinstaDesktopSecurity;

        // Initialize the target security descriptor for Desktop
        if (bDesktopDaclPresent && !InitializeSecurityDescriptor(&sdNewDesktop, SECURITY_DESCRIPTOR_REVISION)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        // Initialize the target security descriptor for Window station
        if(bWinstaDaclPresent && !InitializeSecurityDescriptor(&sdNewWinsta,SECURITY_DESCRIPTOR_REVISION)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        // Apply new ACL to the Desktop security descriptor
        if(bDesktopDaclPresent && !SetSecurityDescriptorDacl(&sdNewDesktop,TRUE,pNewDesktopDacl,bDaclDefaultDesktop)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        // Apply new ACL to the Window station security descriptor
        if(bWinstaDaclPresent && !SetSecurityDescriptorDacl(&sdNewWinsta, TRUE, pNewWinstaDacl, bDaclDefaultWinsta)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        // Apply security descriptors with new DACLs to Desktop and Window station
        if (bDesktopDaclPresent && !SetUserObjectSecurity(hDesktop, &si,&sdNewDesktop)) { hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }

        if(bWinstaDaclPresent && !SetUserObjectSecurity(hWinsta,&si,&sdNewWinsta)) {hr = GetLastError(); goto return_AdjustWinstaDesktopSecurity; }
        hr = S_OK;

        return_AdjustWinstaDesktopSecurity:
        if (sdDesktop != NULL) HeapFree(GetProcessHeap(), 0, sdDesktop);
        if (sdWinsta != NULL) HeapFree(GetProcessHeap(), 0, sdWinsta);
        if (pNewDesktopDacl != NULL) HeapFree(GetProcessHeap(), 0, pNewDesktopDacl);
        if (pNewWinstaDacl != NULL) HeapFree(GetProcessHeap(), 0, pNewWinstaDacl);
        return hr;

    } catch(...){
        if (sdDesktop != NULL) HeapFree(GetProcessHeap(), 0, sdDesktop);
        if (sdWinsta != NULL) HeapFree(GetProcessHeap(), 0, sdWinsta);
        if (pNewDesktopDacl != NULL) HeapFree(GetProcessHeap(), 0, pNewDesktopDacl);
        if (pNewWinstaDacl != NULL) HeapFree(GetProcessHeap(), 0, pNewWinstaDacl);
    }
    return E_UNEXPECTED;
}
//---------------------------------------------------------------------------
HRESULT GrantDesktopAccess(HANDLE hToken)
{
    HWINSTA hWinsta = NULL;
    HDESK   hDesktop = NULL;
    PSID    pLogonSid = NULL;
    HRESULT hr = E_FAIL;

    try {
        if ((hr = RetrieveLogonSid(hToken, &pLogonSid))!=S_OK) return hr;

        hWinsta=GetProcessWindowStation();
        hDesktop=GetThreadDesktop(GetCurrentThreadId());
         
        if (!SetHandleInformation(hDesktop, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) { hr = GetLastError(); goto return_GrantDesktopAccess; }

        if (!SetHandleInformation(hWinsta, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) { hr = GetLastError(); goto return_GrantDesktopAccess; }
        hr = AdjustWinstaDesktopSecurity(hWinsta, hDesktop, pLogonSid, true, hToken);
        
        return_GrantDesktopAccess:
        if(pLogonSid != NULL) HeapFree(GetProcessHeap(), 0, pLogonSid);
        return hr;

    } catch(...){
        if(pLogonSid != NULL)
            HeapFree(GetProcessHeap(), 0, pLogonSid);
    }
    return E_UNEXPECTED;
}
//---------------------------------------------------------------------------
bool CopyToClipBoard(char *text)
{
    if (!text | !text[0]) return false;
    DWORD len;
    HGLOBAL hgbl;
    char temp[MAX_PATH];
    char *pmem;
  
    len = strlen(text);
    hgbl = GlobalAlloc(GHND, len + 1);
    if(!hgbl) return false;
    pmem = (char*)GlobalLock(hgbl);
    strcpy(pmem,text);
    GlobalUnlock(hgbl);
    OpenClipboard(NULL);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, hgbl);
    CloseClipboard();
  
    return true;
}
//---------------------------------------------------------------------------
char *Encrypt(char *data, int length)
{
    char *ret_encrypted;
    char IV[33]; // 16, 24 or 32
    char KEY[33]; // 16, 24 or 32
    char *p_dataIn;
    char *p_dataOut;
    int block_num;
    int totalbytes;
    Base64 b64;

    block_num=length/BLOCK_SIZE;
    if(length%BLOCK_SIZE) block_num++;
    totalbytes=block_num*BLOCK_SIZE;

    p_dataIn=new char[totalbytes];
    p_dataOut=new char[totalbytes];
    memset(p_dataIn,0,totalbytes);
    memset(p_dataOut,0,totalbytes);

    CRijndael oRijndael;
    strcpy(IV, oRijndael.GenerateIV(IV_SIZE)); // IV Salt
    strcpy(KEY, oRijndael.GenerateIV(KEY_SIZE)); // Rand Key
    oRijndael.MakeKey(KEY, IV, KEY_SIZE, IV_SIZE);

    memcpy(p_dataIn, data, length);
    oRijndael.Encrypt(p_dataIn, p_dataOut, totalbytes, CRijndael::CBC); // using p_dataIn because oRijndael.Encrypt need totalbytes to be a multiple of blockSize

    char *b64enc=b64.Encode(IV, IV_SIZE);
    char checksum[CHECK_SIZE+1]={0}; // string to check decoded string integrity
    memcpy(checksum, b64enc, CHECK_SIZE);

    int cryptCmd_length = totalbytes + IV_SIZE + KEY_SIZE + CHECK_SIZE;
    char *p_cryptCmd=new char[cryptCmd_length];
    memcpy(p_cryptCmd, checksum, CHECK_SIZE);
    memcpy(p_cryptCmd + CHECK_SIZE, IV, IV_SIZE);
    memcpy(p_cryptCmd + CHECK_SIZE + IV_SIZE, KEY, KEY_SIZE);
    memcpy(p_cryptCmd + CHECK_SIZE + IV_SIZE + KEY_SIZE, p_dataOut, totalbytes);

    b64enc=b64.Encode(p_cryptCmd, cryptCmd_length);

    ret_encrypted = new char[strlen(b64enc)+1];
    memset(ret_encrypted,0,strlen(b64enc)+1);
    strcpy(ret_encrypted, b64enc);

    delete[] p_cryptCmd;
    delete[] p_dataIn;
    delete[] p_dataOut;
    
    CopyToClipBoard(ret_encrypted);

    return ret_encrypted;
}
//---------------------------------------------------------------------------
char *Decrypt(char *encrypted, int *out_len = NULL)
{
    if (!encrypted) return NULL;
    char *ret_decrypted;
    char IV[33]={0}; // 16, 24 or 32
    char KEY[33]={0}; // 16, 24 or 32
    char *data;
    int block_num;
    int totalbytes;
    Base64 b64;
    size_t output_len;

    if (out_len) *out_len = 0;

    char *b64dec=b64.Decode(encrypted, strlen(encrypted), &output_len);
    if (!b64dec || output_len <= CHECK_SIZE + IV_SIZE + KEY_SIZE ) return NULL;

    char checksum[CHECK_SIZE+1]={0}; // string to check decoded string integrity
    memcpy(checksum, b64dec, CHECK_SIZE);
    memcpy(IV, b64dec + CHECK_SIZE, IV_SIZE);
    memcpy(KEY, b64dec + CHECK_SIZE + IV_SIZE, KEY_SIZE);
    data = b64dec + CHECK_SIZE + IV_SIZE + KEY_SIZE;

    for ( int i = 0; i < CHECK_SIZE; i++)
        if( b64dec[i] != checksum[i] ) return NULL;

    totalbytes = output_len - CHECK_SIZE - IV_SIZE - KEY_SIZE;
    if (totalbytes%BLOCK_SIZE != 0) return NULL;
    ret_decrypted=new char[totalbytes];
    memset(ret_decrypted,0,totalbytes);

    CRijndael oRijndael;
    oRijndael.MakeKey(KEY, IV, KEY_SIZE, IV_SIZE);
    oRijndael.Decrypt(data, ret_decrypted, totalbytes, CRijndael::CBC);

    if (out_len) *out_len = totalbytes;
    return ret_decrypted;
}
//---------------------------------------------------------------------------
void DeleteDynamic()
{
    if (!argv_dynamic) return;
    for(int i=0; i < argc_dynamic; i++) {
        delete[] argv_dynamic[i];
    }
    delete[] argv_dynamic;
}
//---------------------------------------------------------------------------
DWORD CommandRunAs (char* szCommandLine, char* szUsername,  char* szPassword,  char* szDomain,bool bWaitToTerminate=true, bool bShowWindow=true)
{
    DWORD dwExitCode = 0;
    DWORD dwCreationFlags = NULL;
    LPVOID lpEnvironment = NULL;
    PROCESS_INFORMATION pi = {0};
    HANDLE hToken;
    
    char szCurrentDirectory[MAX_PATH];
    GetModuleFileName( 0, szCurrentDirectory, sizeof szCurrentDirectory / sizeof *szCurrentDirectory );
    char *pc=strrchr(szCurrentDirectory,'\\');
    *pc = '\0';

    // If user is "LocalSystem" then CreateProcessWithLogonW() is not used.
    // This function cannot be called from a process that is running under the "LocalSystem" account and this can
    // potentially happen for example by running "ExecAs.exe -i ExecAs.exe -r -u -d -p command" without active user session.
    if (IsLocalSystem())
    {
        STARTUPINFO si = {0};
        si.cb=sizeof(STARTUPINFO);

        if (!bShowWindow)
        {
            dwCreationFlags |= CREATE_NO_WINDOW;
            si.dwFlags |= STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
        }
        
        if (!LogonUser(szUsername, szDomain, szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
            DisplayError("LogonUser");
    
        if (CreateEnvironmentBlock(&lpEnvironment, hToken, TRUE))
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    
        if (!CreateProcessAsUser(hToken, 0, szCommandLine, 0, 0, FALSE, dwCreationFlags, lpEnvironment, szCurrentDirectory, &si, &pi ))
        {
            if (lpEnvironment != NULL) DestroyEnvironmentBlock(lpEnvironment);
            CloseHandle(hToken);
            DisplayError("CreateProcessAsUser");
        }
    
        if (bWaitToTerminate)
        {
            WaitForSingleObject( pi.hProcess, INFINITE );
            GetExitCodeProcess( pi.hProcess, &dwExitCode );
        }
    
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (lpEnvironment != NULL) DestroyEnvironmentBlock(lpEnvironment);
        CloseHandle(hToken);
    }
    else
    {
        STARTUPINFOW si = {0};
        si.cb=sizeof(STARTUPINFOW);
    
        WCHAR lpCommandLine[8192];
        WCHAR lpUsername[256];
        WCHAR lpDomain[256];
        WCHAR lpPassword[256];
        WCHAR lpCurrentDirectory[512];
      
        if (szCommandLine)
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, szCommandLine, strlen(szCommandLine)+1, lpCommandLine, sizeof lpCommandLine);
        else
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, 0, -1, lpCommandLine, sizeof lpCommandLine);
    
        if (szUsername)
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, szUsername, strlen(szUsername)+1, lpUsername, sizeof lpUsername);
        else
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, 0, -1, lpUsername, sizeof lpUsername);
      
        if (szDomain)
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, szDomain, strlen(szDomain)+1, lpDomain, sizeof lpDomain);
        else
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, 0, -1, lpDomain, sizeof lpDomain);
    
        if (szPassword)
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, szPassword, strlen(szPassword)+1, lpPassword, sizeof lpPassword);
        else
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, 0, -1, lpPassword, sizeof lpPassword);
           
        if (szCurrentDirectory)
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, szCurrentDirectory, strlen(szCurrentDirectory)+1, lpCurrentDirectory, sizeof lpCurrentDirectory);
        else
           MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED, 0, -1, lpCurrentDirectory, sizeof lpCurrentDirectory);


        if (!LogonUser(szUsername, szDomain, szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
            DisplayError("LogonUser");

        if (CreateEnvironmentBlock(&lpEnvironment, hToken, TRUE))
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;

        if( !bShowWindow )
        {
            dwCreationFlags |= CREATE_NO_WINDOW;
            si.dwFlags |= STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
        }

        if( !CreateProcessWithLogonW(
              (LPCWSTR)lpUsername,
              (LPCWSTR)lpDomain,
              (LPCWSTR)lpPassword,
              LOGON_WITH_PROFILE,
              NULL,
              (LPWSTR)lpCommandLine,
              dwCreationFlags,
              lpEnvironment,
              lpCurrentDirectory,
              &si,
              &pi) )
              {
                  CloseHandle(hToken);
                  DestroyEnvironmentBlock(lpEnvironment);
                  DisplayError("CreateProcessWithLogonW");
              }
            
        if (bWaitToTerminate) {
            WaitForSingleObject( pi.hProcess, INFINITE );
            GetExitCodeProcess( pi.hProcess, &dwExitCode );
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (lpEnvironment != NULL) DestroyEnvironmentBlock(lpEnvironment);
        CloseHandle(hToken);
    }

    return dwExitCode;
}
//---------------------------------------------------------------------------
int CheckParams(int argc, char *argv[])
{
    int iCheckParams = 0;
    int indent_first_arg = 0;

    if (strnicmp(argv[1], "-c", 2)==0) indent_first_arg++;
    if (strnicmp(argv[1+indent_first_arg], "-n", 2)==0) indent_first_arg++; // optional -n parameter must be first argument or just after -c
    
    for (int i = 1+indent_first_arg; i < argc; i++) {
        // Case argument is always set or  misplaced return an error
        if ((strnicmp(argv[i], "-d", 2)==0 && (iCheckParams & 0x01)) ||
            (strnicmp(argv[i], "-u", 2)==0 && (iCheckParams & 0x02)) ||
            (strnicmp(argv[i], "-p", 2)==0 && (iCheckParams & 0x04)) ||
            (strnicmp(argv[i], "-s", 2)==0 && (iCheckParams & 0x08)) ||
            (strnicmp(argv[i], "-a", 2)==0 && (iCheckParams & 0x10)) ||
            (strnicmp(argv[i], "-i", 2)==0 && (iCheckParams & 0x20)) ||
            (strnicmp(argv[i], "-e", 2)==0 && (iCheckParams & 0x40)) ||
            (strnicmp(argv[i], "-r", 2)==0 && (iCheckParams & 0x80)) ||
            (strnicmp(argv[i], "-w", 2)==0 && (iCheckParams & 0x100)) ||
            (strnicmp(argv[i], "-h", 2)==0 && (iCheckParams & 0x200)) ||
            (strnicmp(argv[i], "-n", 2)==0) ) return 0; // -n only allowed at position 1 or 2

        if (strnicmp(argv[i], "-d", 2)==0) iCheckParams |= 0x01; // no length check because domain can be empty to use local account
        else if (strnicmp(argv[i], "-u", 2)==0 && strlen(argv[i])>2) iCheckParams |= 0x02;
        else if (strnicmp(argv[i], "-p", 2)==0 && strlen(argv[i])>2) iCheckParams |= 0x04;
        else if (strnicmp(argv[i], "-s", 2)==0) iCheckParams |= 0x08;
        else if (strnicmp(argv[i], "-a", 2)==0 && strlen(argv[i])>2) iCheckParams |= 0x10;
        else if (strnicmp(argv[i], "-i", 2)==0) iCheckParams |= 0x20;
        else if (strnicmp(argv[i], "-e", 2)==0) iCheckParams |= 0x40;
        else if (strnicmp(argv[i], "-r", 2)==0) iCheckParams |= 0x80;
        else if (strnicmp(argv[i], "-w", 2)==0) iCheckParams |= 0x100; // optional
        else if (strnicmp(argv[i], "-h", 2)==0) iCheckParams |= 0x200; // optional
        else break;
        if (i > 5+indent_first_arg) break; // max 'dupwh'+'c'
    }

    // params allowed:     -dup  -s    -a    -i    -e    -rdup
    int allowedParams[] = {0x07, 0x08, 0x10, 0x20, 0x40, 0x87};

    bool bParamsOK = false;
    for (int i =0; i < sizeof(allowedParams)/sizeof(int); i++) {
        if (iCheckParams != allowedParams[i] &&
            iCheckParams != (allowedParams[i]|0x100) && // with option -w
            iCheckParams != (allowedParams[i]|0x200) && // with option -h
            iCheckParams != (allowedParams[i]|0x300) ) // with options -w -h
            continue;
        if (iCheckParams & 0x08 && iCheckParams & 0x200) break; // not allowed '-h' when running as 'system' user
        bParamsOK = true;
        break;
    }

    if (!bParamsOK) return 0;

    //                                  -w                              -h                    -c && -n
    int nOptionalsCount = ((iCheckParams & 0x100) >> 8) + ((iCheckParams & 0x200) >> 9) + indent_first_arg ;

    //                   -s                      -a                    -i                    -e
    if ((iCheckParams & 0x08 || iCheckParams & 0x10 || iCheckParams & 0x20 || iCheckParams & 0x40 ) &&
        argc <= 2 + nOptionalsCount) return 0;

    //                 -rdup
    if ((iCheckParams & 0x87) == 0x87  && argc <= 5 + nOptionalsCount) return 0;

    //                 -dup
    if ((iCheckParams & 0x07) == 0x07 && argc <= 4 + nOptionalsCount) return 0;

    return iCheckParams;
}
//---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int __argc__ = argc;
    char **__argv__ = argv;

    //
    // Case encrypting command line
    //
    if (__argc__ > 2 && strnicmp(__argv__[1], "-c", 2)==0) {
      
        if (!CheckParams(__argc__, __argv__)) PrintUsageAndQuit();
        //
        // Convert **__argv__ to one char array ended with '\0\0'
        //
        // -> Get command arguments length (after "-c")
        size_t argv_length = 0;
        char **it = __argv__+1; // *it=__argv__[1]
        while( *(++it) ) { // start iteration from __argv__[2]
            argv_length += strlen(*it)+1; //for argv length + '0'
        }
        argv_length++; // Add '0'

        // -> Fill data char array with arguments separated by '0'
        char *argv_data = new char[argv_length];
        int index = 0;
        it = __argv__+1; // *it=__argv__[1]
        while( *(++it) ) {
            memcpy(argv_data+index, *it, strlen(*it));
            index += strlen(*it);
            memcpy(argv_data+index, "\0", 1);
            index++;
        }
        memcpy(argv_data+index, "\0", 1);

        //
        // Encode data
        //
        char *encoded_cmd = Encrypt(argv_data, argv_length);
        printf("%s\n", encoded_cmd);
        delete[] encoded_cmd;
        return 0;
    }
    //
    // Case using encrypted argument string then decrypt __argv__ and try to execute command
    //
    else if (__argc__ == 2)
    {
        int index = 0; // index of arguments in __argv__
        int len = 0; // length of each __argv__
        char *decoded_str = NULL;

        // Get base64 string from argv1 or from file pointed by argv1
        if (IsBase64String(__argv__[1]))
            decoded_str = Decrypt(__argv__[1]);
        else
        {
          FILE *fp = fopen(__argv__[1], "r");
          if (fp) {
              fseek(fp, 0, SEEK_END);
              long size = ftell(fp);
              if (size<MAX_CMD_LEN) {
                  fseek(fp, 0, SEEK_SET);
                  char *fdata = new char[size+1];
                  fread(fdata, 1, size, fp);
                  fdata[size]=0;
                  if (!IsBase64String(fdata)) {
                      delete[] fdata;
                      fclose(fp);
                      PrintUsageAndQuit();
                  }
                  decoded_str = Decrypt(fdata);
                  delete[] fdata;
              }
              fclose(fp);
          }
        }

        if (!decoded_str) PrintUsageAndQuit();

        // Count decoded arguments and create new __argv__ array
        char *it_arg = decoded_str;
        argc_dynamic += 1; // +1 to add __argv__[0]
        while (*it_arg) {
          argc_dynamic += 1;
          it_arg += strlen(it_arg)+1;
        }
        argv_dynamic = new char*[argc_dynamic+1]; // +1 to add 'NULL string' ( argv[argc] is guaranteed to be NULL )

        // Copy __argv__[0] to argv_dynamic
        len = strlen(__argv__[0]) + 1;
        argv_dynamic[index] = new char[len];
        strcpy(argv_dynamic[index], __argv__[0]);
        index++;

        // Append decoded __argv__ to argv_dynamic
        it_arg = decoded_str;
        while (*it_arg) {
            len = strlen(it_arg) + 1;
            argv_dynamic[index] = new char[len];
            strcpy(argv_dynamic[index], it_arg);
            index++;
            it_arg += strlen(it_arg)+1;
        }
        argv_dynamic[argc_dynamic] = NULL;

        // Set new __argc__ & __argv__
        __argc__ = argc_dynamic;
        __argv__ = argv_dynamic;

        delete[] decoded_str;
    }

    //
    // Next are other cases (interactive, system, runas...)
    //

    //
    // Set unique global service name
    //
    SYSTEMTIME st;
    GetSystemTime(&st);
    char servicename[256]={0};
    sprintf( servicename, "%s_%d%02d%02d%02d%02d%02d%03d",
                          SERVICE_NAME,
                          st.wYear,
                          st.wMonth,
                          st.wDay,
                          st.wHour,
                          st.wMinute,
                          st.wSecond,
                          st.wMilliseconds );
    g_servicename = servicename;

    //
    // Check command line arguments
    //
    if (1 < __argc__) {
        int iCheckParams = CheckParams(__argc__, __argv__);
        if (!iCheckParams) PrintUsageAndQuit();

        // Hide window's console
        if (strnicmp(__argv__[1], "-n", 2)==0)
            ShowWindow( GetConsoleWindow(), SW_HIDE );

        // Simple RUNAS
        if (iCheckParams & 0x80)
        {          
            LPSTR szcUser = NULL;
            LPSTR szcDomain = NULL;
            LPSTR szcPassword = NULL;
            DWORD index_cmd;

            // Get User, Domain and Password values
            for (DWORD i = 1; i < __argc__; i++) {
                index_cmd = i;
                if (strnicmp(__argv__[i], "-d",2)==0) szcDomain = __argv__[i]+2;
                else if (strnicmp(__argv__[i], "-u", 2)==0) szcUser = __argv__[i]+2;
                else if (strnicmp(__argv__[i], "-p", 2)==0) szcPassword = __argv__[i]+2;
                else if (strnicmp(__argv__[i], "-r", 2)==0) continue;
                else if (strnicmp(__argv__[i], "-w", 2)==0) continue;
                else if (strnicmp(__argv__[i], "-h", 2)==0) continue;
                else if (strnicmp(__argv__[i], "-n", 2)==0) continue;
                else break;
            }
            
            // Make command line
            CHAR cmd[MAX_CMD_LEN];
            CHAR* dst = cmd;
            for (DWORD i = index_cmd; i < __argc__; i++) {
                if ( dst != cmd ) *dst++ = ' ';
                strcpy( dst, __argv__[i] );
                dst += strlen(__argv__[i]);
            }
            *dst = '\0';

            // Execute command
            DWORD dwExitCode = CommandRunAs(cmd, szcUser, szcPassword, szcDomain,
                (iCheckParams & 0x100)?true:false, (iCheckParams & 0x200)?false:true);
            
            if (dwExitCode) DisplayError("CommandRunAs", dwExitCode);
            DisplayError(NULL, dwExitCode);
        }

    } else if ( 1 == __argc__ ) {
        // try to detect whether we are being launched by the SCM
        // or by the interactive user, who should have passed cmd line args
        if ( !IsLocalSystem() )
            PrintUsageAndQuit();

        SERVICE_TABLE_ENTRY ste[] = {
            { (LPSTR)g_servicename, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
            { 0, 0 }
        };
        StartServiceCtrlDispatcher( ste );
        return 0;
    }
    if ( !IsAdmin() )
        Quit( "You must be a member of the local Administrator's group to run this program with these options" );

    //
    // Check if service running
    //
    SC_HANDLE hscm = OpenSCManager(
        NULL,                    // local computer
        NULL,                    // servicesActive database
        SC_MANAGER_ENUMERATE_SERVICE );  // Required to call the EnumServicesStatus

    SC_HANDLE hsvc = NULL;
    hsvc = OpenService( hscm, g_servicename, SERVICE_INTERROGATE );
    if ( hsvc ) {
        CloseServiceHandle( hsvc );
        CloseServiceHandle( hscm );
        Quit( "ExecAs.exe can not be executed because another instance is running" );
    }

    //
    // Initialize file mapping object to get returned value from launched command
    //
    char sFileMap[MAX_PATH];
    sprintf(sFileMap, "Global\\filemap_%s", g_servicename);
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE,0,PAGE_READWRITE,0,0x4000,sFileMap);
    int* mData = (int*)MapViewOfFile(hFileMap,FILE_MAP_ALL_ACCESS,0,0,0);
    *mData = 0;

    //
    // Append service name to argv
    //
    int ignore_first_arg = 0; // -n is not used by service
    if (strnicmp(__argv__[1], "-n", 2)==0) ignore_first_arg = 1;

    int newargc = __argc__ + 1 - ignore_first_arg; // add 'service name' and remove -n
    char **newargv = new char*[newargc+1]; // +1 to add 'NULL string' ( argv[argc] is guaranteed to be NULL )
    // Copy argv in newargv
    for(int i=0; i < __argc__; i++) {
        if (ignore_first_arg && i==ignore_first_arg) continue; // ignore -n
        int len = strlen(__argv__[i]) + 1;
        int index = i-ignore_first_arg;
        if (ignore_first_arg && i==0) index = 0;
        newargv[index] = new char[len];
        strcpy(newargv[index], __argv__[i]);
    }
    // Add 'service name'
    int len = strlen(g_servicename) + 1;
    newargv[newargc-1] = new char[len];
    strcpy(newargv[newargc-1], g_servicename);
    // Add 'NULL string'
    newargv[newargc] = NULL;

    DeleteDynamic();

    //
    // Start this program as a service that will execute command from "argv+1" arguments
    //
    StartAsService( newargc - 1, (const char**)newargv + 1 );

    for(int i=0; i < newargc; i++) {
        delete[] newargv[i];
    }
    delete[] newargv;
    
    //
    // Wait while service running
    //
    do {
      hsvc = OpenService( hscm, g_servicename, SERVICE_INTERROGATE );
      CloseServiceHandle( hsvc );
      Sleep(100);
    }
    while (hsvc);
    CloseServiceHandle( hscm );

    int retval = *mData;
    UnmapViewOfFile(mData);
    CloseHandle(hFileMap);

    DisplayError(NULL, retval);
}
//---------------------------------------------------------------------------