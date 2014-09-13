// NTHashTickler.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <conio.h>
#include <Windows.h>
#include <bcrypt.h>

bool shouldStop = false;
int maxPasswordLength = 12;
//CRITICAL_SECTION criticalSection;
HANDLE hMutex;
unsigned long long hashesGenerated = 0;
unsigned char inputHashBytes[16] = { 0 };
HANDLE *hThreads = NULL;
BCRYPT_ALG_HANDLE phAlgorithm = NULL;
const wchar_t * version = L"1.0";
const char validChars[] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
							0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
							0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x4A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
							0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
							0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E };

void PrintHelpText()
{
	wprintf(L"\nNTHashTickler v%s", version);
	wprintf(L"\nWritten by Ryan Ries, myotherpcisacloud.com");
	wprintf(L"\n\nUsage: C:\\> NTHashTickler.exe d79e1c308aa5bbcdeea8ed63df412da9 [8]");
	wprintf(L"\n\nUses brute force to find a plain text input that generates an");
	wprintf(L"\nNT hash that matches the one supplied by the user. An NT (or NTLM)");
	wprintf(L"\nhash is the MD4 hash of the Unicode little endian plain text.");
	wprintf(L"\nHexadecimal hash strings are not case sensitive.");
	wprintf(L"\nThe second argument is optional and specifies the maximum password");
	wprintf(L"\nlength for which to generate hashes. Default is 12. Smaller key spaces");
	wprintf(L"\ntake less time to search.\n");
}

wchar_t * DisplayError(DWORD NTStatusCode)
{
	wchar_t * message = NULL;
	HMODULE hMod = LoadLibrary(L"NTDLL.DLL");
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_FROM_HMODULE,
		hMod,
		NTStatusCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(wchar_t *)&message, 0, NULL);	

	if (hMod != 0)
		FreeLibrary(hMod);

	return message;
}

bool IsMD4HashString(wchar_t * input)
{
	const wchar_t nibbles[] = { L"0123456789abcdef" };	

	if (wcslen(input) != 32)
		return false;

	for (int x = 0; input[x]; x++)
		input[x] = tolower(input[x]);	

	for (int x = 0; input[x]; x++)
	{
		bool isNibble = false;
		for (int y = 0; y < 16; y++)
		{
			if (nibbles[y] == input[x])			
				isNibble = true;			
		}
		if (isNibble == false)
			return false;
	}

	return true;
}

DWORD WINAPI Interrupt(LPVOID lpParam)
{
	_getch();
	//EnterCriticalSection(&criticalSection);
	WaitForSingleObject(hMutex, INFINITE);
	shouldStop = true;
	ReleaseMutex(hMutex);
	//LeaveCriticalSection(&criticalSection);
	return 0;
}

DWORD WINAPI WorkerThread(LPVOID lpParam)
{
	unsigned long long threadLocalHashesGenerated = 0;
	while (true)
	{
		if (shouldStop)
			break;

		int passwordLength = rand() % maxPasswordLength + 1;
		unsigned char * hashOut = new unsigned char[16];
		unsigned char * randomBytes = new unsigned char[passwordLength * 2];

		BCryptGenRandom(NULL, randomBytes, passwordLength * 2, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

		for (int x = 0; x < passwordLength; x++)
		{
			randomBytes[x * 2] = validChars[randomBytes[x * 2] % sizeof(validChars)];
			randomBytes[(x * 2) + 1] = '\0';
		}

		BCRYPT_HASH_HANDLE phHash = NULL;
		BCryptCreateHash(phAlgorithm, &phHash, 0, 0, 0, 0, 0);
		BCryptHashData(phHash, randomBytes, passwordLength * 2, 0);
		BCryptFinishHash(phHash, hashOut, 16, 0);
		BCryptDestroyHash(phHash);
		threadLocalHashesGenerated++;

		if (memcmp(inputHashBytes, hashOut, 16) == 0)
		{
			//EnterCriticalSection(&criticalSection);
			WaitForSingleObject(hMutex, INFINITE);
			wprintf(L"\nMatch found!\n");

			wprintf(L"Pass Len: %2i\n", passwordLength);
			wprintf(L"Chars in: ");
			for (int x = 0; x < passwordLength * 2; x += 2)
			{
				wprintf(L"%2c %2c ", randomBytes[x], randomBytes[x + 1]);
			}
			wprintf(L"\nBytes in: ");
			for (int x = 0; x < passwordLength * 2; x += 2)
			{
				wprintf(L"%02x %02x ", randomBytes[x], randomBytes[x + 1]);
			}
			wprintf(L"\n");
			wprintf(L"Hash out: ");
			for (int x = 0; x < 16; x++)
			{
				wprintf(L"%02x ", hashOut[x]);
			}
			wprintf(L"\n\n");			
			shouldStop = true;
			//LeaveCriticalSection(&criticalSection);
			ReleaseMutex(hMutex);
		}

		delete hashOut;
		delete randomBytes;
	}
	WaitForSingleObject(hMutex, INFINITE);
	hashesGenerated += threadLocalHashesGenerated;
	ReleaseMutex(hMutex);
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	NTSTATUS status = NULL;
	SYSTEM_INFO systemInfo;
	LARGE_INTEGER startingTime, endingTime;
	LARGE_INTEGER frequency;	

	hMutex = CreateMutex(NULL, FALSE, L"Tickler");
	//InitializeCriticalSection(&criticalSection);

	wprintf(L"\n");
	if ((argc != 2) & (argc != 3))
	{
		PrintHelpText();
		return 0;
	}
	
	if (IsMD4HashString(argv[1]) == false)
	{
		PrintHelpText();
		return 0;
	}

	if (argc == 3)	
		maxPasswordLength = _wtoi(argv[2]);

	if ((maxPasswordLength < 1) || (maxPasswordLength > 120))
	{
		PrintHelpText();
		return 0;
	}
	
	for (int x = 0; x < 32; x += 2)
	{
		char b[2] = { 0, 0 };
		b[0] = (char)argv[1][x];
		b[1] = (char)argv[1][x + 1];
		inputHashBytes[x / 2] = (char)strtoul(b, NULL, 16);
	}

	status = BCryptOpenAlgorithmProvider(&phAlgorithm, BCRYPT_MD4_ALGORITHM, NULL, 0);
	if (status != 0)
	{
		wprintf(L"ERROR: Failed to initialize MD4 algorithm provider.\nBCryptOpenAlgorithmProvider returned %s", DisplayError(status));
		return status;
	}
	else
	{
		wprintf(L"BCryptOpenAlgorithmProvider: %s", DisplayError(status));
	}

	QueryPerformanceFrequency(&frequency);
	if (frequency.QuadPart == 0)
	{
		wprintf(L"ERROR: Unable to query performance frequency!");
		return 1;
	}

	GetSystemInfo(&systemInfo);
	if (systemInfo.dwNumberOfProcessors < 1)
	{
		wprintf(L"ERROR: Unable to find number of CPUs!");
		return 1;
	}
	
	wprintf(L"%i CPUs found.\n", systemInfo.dwNumberOfProcessors);
	wprintf(L"Max password length is %i characters.\n", maxPasswordLength);
	wprintf(L"Searching for %s as MD4(Unicode(password)).\n", argv[1]);
	wprintf(L"Hashing will now commence. Press any key to interrupt the program.\n");
	QueryPerformanceCounter(&startingTime);
	
	hThreads = new HANDLE[systemInfo.dwNumberOfProcessors];
	for (unsigned int x = 0; x < systemInfo.dwNumberOfProcessors; x++)
	{
		hThreads[x] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
	}

	CreateThread(NULL, 0, Interrupt, NULL, 0, NULL);

	WaitForMultipleObjects(systemInfo.dwNumberOfProcessors, hThreads, TRUE, INFINITE);
	CloseHandle(hMutex);
	QueryPerformanceCounter(&endingTime);	

	//DeleteCriticalSection(&criticalSection);
	
	delete hThreads;

	if (phAlgorithm != NULL)
		BCryptCloseAlgorithmProvider(phAlgorithm, 0);

	double elapsed = (double)(endingTime.QuadPart - startingTime.QuadPart) / frequency.QuadPart;
	wprintf(L"\n%lu hashes generated in %.2f seconds (%.0f hashes/second.)\n", hashesGenerated, elapsed, hashesGenerated / elapsed);
	
	return 0;
}

