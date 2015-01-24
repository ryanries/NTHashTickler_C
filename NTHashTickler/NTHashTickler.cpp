// NTHashTickler.cpp : Defines the entry point for the console application.
// Ryan Ries, myotherpcisacloud.com

#define _CRT_RAND_S
#include <conio.h>
#include <stdint.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

BOOL G_ShouldStop = FALSE;
uint8_t MaxPasswordLength = 12;
CRITICAL_SECTION CritSec;
uint64_t hashesGenerated = 0;
unsigned char inputHashBytes[16] = { 0 };
HANDLE *hThreads = NULL;
const char *Version = "1.3";
const char validChars[] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
							0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
							0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x4A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
							0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
							0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E };

// These are initialization values for the MD4 hash algorithm. See RFC 1320.
const uint32_t INIT_A = 0x67452301;
const uint32_t INIT_B = 0xefcdab89;
const uint32_t INIT_C = 0x98badcfe;
const uint32_t INIT_D = 0x10325476;
const uint32_t SQRT_2 = 0x5a827999;
const uint32_t SQRT_3 = 0x6ed9eba1;

void PrintHelpText()
{
	printf("\nNTHashTickler v%s", Version);
	printf("\nWritten by Ryan Ries, myotherpcisacloud.com");
	printf("\n\nUsage: C:\\> NTHashTickler.exe d79e1c308aa5bbcdeea8ed63df412da9 [12]");
	printf("\n\nUses brute force to find a plain text input that generates an");
	printf("\nNT hash that matches the one supplied by the user. An NT (or NTLM)");
	printf("\nhash is the MD4 hash of the Unicode little endian plain text.");
	printf("\nHexadecimal hash strings are not case sensitive.");
	printf("\nThe second argument is optional and specifies the maximum password");
	printf("\nlength for which to generate hashes. Default is 12. Smaller key spaces");
	printf("\ntake less time to search.\n");
}

// Return 0 if the input string is not a valid-looking MD4 hash. Return 1 if it is.
char IsMD4HashString(char *input)
{
	const char nibbles[] = { "0123456789abcdefABCDEF" };

	if (strlen(input) != 32)	
		return(0);	

	for (int x = 0; input[x]; x++)
	{
		short isNibble = 0;
		for (int y = 0; y < (sizeof(nibbles) - 1); y++)
		{
			if (nibbles[y] == input[x])
			{
				isNibble = 1;
				break;
			}
		}
		if (isNibble == 0)
		{
			OutputDebugString(L"Invalid character was found in input string!\n");
			return(0);
		}
	}
	return(1);
}

void NTHash(unsigned char *password, int length, uint32_t *output)
{	
	uint32_t nt_buffer[16] = { 0 };
	uint8_t i = 0;

	for (; i < length / 2; i++)
		nt_buffer[i] = password[2 * i] | (password[2 * i + 1] << 16);

	// Padding
	if (length % 2 == 1)
		nt_buffer[i] = password[length - 1] | 0x800000;
	else
		nt_buffer[i] = 0x80;

	nt_buffer[14] = length << 4;

	uint32_t a = INIT_A;
	uint32_t b = INIT_B;
	uint32_t c = INIT_C;
	uint32_t d = INIT_D;

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

	output[0] = a + INIT_A;
	output[1] = b + INIT_B;
	output[2] = c + INIT_C;
	output[3] = d + INIT_D;
}

DWORD WINAPI Interrupt(LPVOID LParam)
{
	UNREFERENCED_PARAMETER(LParam);		
	_getch();
	G_ShouldStop = TRUE;
	return(0);
}

DWORD WINAPI WorkerThread(LPVOID LParam)
{
	UNREFERENCED_PARAMETER(LParam);

	uint64_t Rand = 0;
	uint64_t ThreadLocalHashesGenerated = 0;
	uint32_t hashBuffer[4] = { 0 };

	while (G_ShouldStop == FALSE)
	{
		if (G_ShouldStop == TRUE)
		{
			break;
		}
		uint8_t PasswordLength = (Rand % MaxPasswordLength) + 1;
		uint8_t hashOut[16];
		uint8_t RandomBytes[64] = { 0 };

		for (uint8_t x = 0; x < PasswordLength; x++)
		{
			Rand = __rdtsc() + rand();
			RandomBytes[x] = validChars[Rand % sizeof(validChars)];
		}

		NTHash(RandomBytes, PasswordLength, hashBuffer);

		hashOut[3] = (uint8_t)((hashBuffer[0] & 0xFF000000) >> 24);
		hashOut[2] = (uint8_t)((hashBuffer[0] & 0x00FF0000) >> 16);
		hashOut[1] = (uint8_t)((hashBuffer[0] & 0x0000FF00) >> 8);
		hashOut[0] = (uint8_t)((hashBuffer[0] & 0x000000FF));

		hashOut[7] = (uint8_t)((hashBuffer[1] & 0xFF000000) >> 24);
		hashOut[6] = (uint8_t)((hashBuffer[1] & 0x00FF0000) >> 16);
		hashOut[5] = (uint8_t)((hashBuffer[1] & 0x0000FF00) >> 8);
		hashOut[4] = (uint8_t)((hashBuffer[1] & 0x000000FF));

		hashOut[11] = (uint8_t)((hashBuffer[2] & 0xFF000000) >> 24);
		hashOut[10] = (uint8_t)((hashBuffer[2] & 0x00FF0000) >> 16);
		hashOut[9]  = (uint8_t)((hashBuffer[2] & 0x0000FF00) >> 8);
		hashOut[8]  = (uint8_t)((hashBuffer[2] & 0x000000FF));

		hashOut[15] = (uint8_t)((hashBuffer[3] & 0xFF000000) >> 24);
		hashOut[14] = (uint8_t)((hashBuffer[3] & 0x00FF0000) >> 16);
		hashOut[13] = (uint8_t)((hashBuffer[3] & 0x0000FF00) >> 8);
		hashOut[12] = (uint8_t)((hashBuffer[3] & 0x000000FF));
		
		ThreadLocalHashesGenerated++;

		if (memcmp(inputHashBytes, hashOut, 16) == 0)
		{
			EnterCriticalSection(&CritSec);
			if (G_ShouldStop)
			{
				LeaveCriticalSection(&CritSec);
				break;
			}
			printf("\nMatch found!\n");

			printf("Pass Len: %2d\n", PasswordLength);
			printf("Chars in: ");
			for (unsigned int x = 0; x < PasswordLength; x++)
			{
				printf("%2c ", RandomBytes[x]);
			}
			printf("\nBytes in: ");
			for (unsigned int x = 0; x < PasswordLength; x++)
			{
				printf("%02x ", RandomBytes[x]);
			}
			printf("\n");
			printf("Hash out: ");
			for (unsigned int x = 0; x < 16; x++)
			{
				printf("%02x ", hashOut[x]);
			}
			printf("\n\n");			
			G_ShouldStop = TRUE;
			LeaveCriticalSection(&CritSec);
		}				
	}

	EnterCriticalSection(&CritSec);
	hashesGenerated += ThreadLocalHashesGenerated;
	LeaveCriticalSection(&CritSec);

	return(0);
}

int main(int argc, char *argv[])
{	
	SYSTEM_INFO SystemInfo            = { 0 };
	LARGE_INTEGER StartingTime        = { 0 };
	LARGE_INTEGER EndingTime          = { 0 };
	LARGE_INTEGER Frequency           = { 0 };
	LARGE_INTEGER ElapsedMicroseconds = { 0 };
	float ElapsedSeconds              = 0;

	if (!InitializeCriticalSectionAndSpinCount(&CritSec, 0xff000000))
	{
		printf("ERROR: Failed to initialize critical section!\n");
		return(1);
	}

	printf("\n");

	if ((argc != 2) & (argc != 3))
	{
		PrintHelpText();
		return(0);
	}

	if (IsMD4HashString(argv[1]) == 0)
	{
		PrintHelpText();
		return(0);
	}

	if (argc == 3)
	{
		MaxPasswordLength = (uint8_t)atoi(argv[2]);
	}

	if ((MaxPasswordLength < 1) || (MaxPasswordLength > 30))
	{
		PrintHelpText();
		return(0);
	}
	
	for (int x = 0; x < 32; x += 2)
	{
		char b[2] = { 0, 0 };
		b[0] = (char)argv[1][x];
		b[1] = (char)argv[1][x + 1];
		inputHashBytes[x / 2] = (char)strtoul(b, NULL, 16);
	}

	QueryPerformanceFrequency(&Frequency);
	if (Frequency.QuadPart == 0)
	{
		printf("ERROR: Unable to query performance frequency!\n");
		return(1);
	}

	GetSystemInfo(&SystemInfo);
	if (SystemInfo.dwNumberOfProcessors < 1)
	{
		printf("ERROR: Unable to find number of CPUs!\n");
		return(1);
	}
	
	printf("%i CPUs found.\n", SystemInfo.dwNumberOfProcessors);
	printf("Max password length is %i characters.\n", MaxPasswordLength);
	printf("Searching for %s as MD4(Unicode(password)).\n", argv[1]);
	printf("Hashing will now commence. Press any key to interrupt the program.\n");
	QueryPerformanceCounter(&StartingTime);
	
	CreateThread(NULL, 0, Interrupt, NULL, 0, NULL);

	hThreads = new HANDLE[SystemInfo.dwNumberOfProcessors];
	for (unsigned int x = 0; x < SystemInfo.dwNumberOfProcessors; x++)
	{
		hThreads[x] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
	}

	WaitForMultipleObjects(SystemInfo.dwNumberOfProcessors, hThreads, TRUE, INFINITE);
	
	QueryPerformanceCounter(&EndingTime);

	ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000;
	ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;

	ElapsedSeconds = (ElapsedMicroseconds.QuadPart / 1000.0f) / 1000.0f;

	printf("\n%lu hashes generated in %.2f seconds (%d hashes/second.)\n", hashesGenerated, ElapsedSeconds, (int)(hashesGenerated / ElapsedSeconds));
	return(0);
}