#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include "injector.h"
#include <stdio.h>
#include <string>

using namespace KeyAuth;
using namespace std;


std::string name = ("");
std::string ownerid = ("");
std::string secret = ("");
std::string version = ("1.0");

api KeyAuthApp(name, ownerid, secret, version);


bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

DWORD GetProcessIdByName(const wchar_t* name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}



int main()
{
	SetConsoleTitleA(XorStr("Loader").c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init();
	system(XorStr("cls").c_str());
	
	std::cout << XorStr("\n\n [1]License key only\n\n ");

	int option;
	std::string username;
	std::string password;
	std::string key;

	
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.license(key);
		
	

	std::vector<std::uint8_t> rawData = KeyAuthApp.download("12345"); //.dll fileID here






	wchar_t* dllPath;
	DWORD PID = GetProcessIdByName(L"SNMAS-Win64-Shipping.exe"); //Game.exe here


	if (PID == 0) {
		printf("Process not found\n");
		system("pause");
		return -1;
	}

	printf("Process pid: %d\n", PID);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return -2;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		printf("Invalid Process Architecture.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return -3;
	}

	printf("Mapping...\n");
	if (!ManualMap(hProc, &rawData[0]))
	{
		CloseHandle(hProc);
		printf("Error while mapping.\n");
		system("PAUSE");
		return -4;
	}

	CloseHandle(hProc);
	printf("OK\n");
	return 0;
}






















