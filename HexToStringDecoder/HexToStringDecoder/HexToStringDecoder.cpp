#include <string>
#include <iostream>
#include <windows.h>


void StringToHex(const std::string str, std::string& hexstr, bool fUpperCase = false)
{
	// Convert string of chars to its representative string of hex numbers

	hexstr.resize(str.size() * 2);
	const size_t a = fUpperCase ? 'A' - 1 : 'a' - 1;

	for (size_t i = 0, c = str[0] & 0xFF; i < hexstr.size(); c = str[i / 2] & 0xFF)
	{
		hexstr[i++] = c > 0x9F ? (c / 16 - 9) | a : c / 16 | '0';
		hexstr[i++] = (c & 0xF) > 9 ? (c % 16 - 9) | a : c % 16 | '0';
	}

	// Reverse the calculated Hex string to further obfuscate the data
	std::reverse(hexstr.begin(), hexstr.end());

}

void HexToString(const std::string hexstr, std::string & str)
{
	// Convert string of hex numbers to its equivalent char-stream
	
	// Reverse the inputed Hex string to get back to the original Hex string before doing the decoding
	std::string hextmp(hexstr);
	std::reverse(hextmp.begin(), hextmp.end());

	str.resize((hextmp.size() + 1) / 2);

	for (size_t i = 0, j = 0; i < str.size(); i++, j++)
	{
		str[i] = (hextmp[j] & '@' ? hextmp[j] + 9 : hextmp[j]) << 4, j++;
		str[i] |= (hextmp[j] & '@' ? hextmp[j] + 9 : hextmp[j]) & 0xF;
	}
}


int main(int argc, char* argv[])
{ 
	std::string strToDecode = "";

	if (argc > 1)
	{
		strToDecode = argv[1];

		std::cout << "Hex Input:      " << strToDecode << std::endl;

		HexToString(strToDecode, strToDecode);
		//std::cout << "Hex format:     " << strToEncode << std::endl;// << "  <--- copy this value into your code to obfuscate the real string" << std::endl;
		//std::reverse(strToEncode.begin(), strToEncode.end());
		std::cout << std::endl << "Decoded string: " << strToDecode << std::endl;

		//std::reverse(strToEncode.begin(), strToEncode.end());
		StringToHex(strToDecode, strToDecode);
		std::cout << std::endl << "Hex Encoded:    " << strToDecode << std::endl;

	}
	else
	{
		std::cout << std::endl << "Missing required parameter." << std::endl;
		std::cout << std::endl << "Usage: HexToStringDecoder.exe \"Enter the Hex string you want to convert to real string\"" << std::endl;
		//std::cout << std::endl << "Copy the generated Hex value into your code.  This is the obfuscated value" << std::endl;
		//std::cout << "to deter strings detection during static analysis." << std::endl;
		/*std::cout << "   For example:" << std::endl;
		std::cout << "      std::string mystring = \"Hex_value\";" << std::endl;
		std::cout << std::endl << "Then call HexToString(s, s) to decode the Hex value into the real string for usage." << std::endl;
		std::cout << "   For example:" << std::endl;
		std::cout << "      HexToString(mystring, mystring);" << std::endl;*/
	}
}


