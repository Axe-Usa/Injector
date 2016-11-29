#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <wchar.h>
#include <iostream>
using namespace std;


void error(char *err);

HANDLE myProc = NULL;

void error(char *err)
{
	if (myProc != NULL) CloseHandle(myProc);
	printf("%s", err);
	exit(0);
}



int main(int argc, char *argv[])
{
	HANDLE processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pInfo;
	BOOL st = TRUE;
	pInfo.dwSize = sizeof(PROCESSENTRY32);
	Process32First(processList, &pInfo);
	int myPid = 0;
	do
	{
		std::wstring name(L"explorer.exe");
		const wchar_t* szName = name.c_str();
		if (wcscmp(pInfo.szExeFile, szName) == 0)
		{
			myPid = pInfo.th32ProcessID;
			cout << myPid << endl;
			break;
		}
		Process32Next(processList, &pInfo);
	} while (st != FALSE);
	
	// Abrir el proceso
	printf("[+] Opening process %i\n", myPid);
	myProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, myPid);
	if (myProc == NULL) error("[-] Error abriendo proceso.\n");
	else printf("[+] Proceso abierto.\n");
	
	// Reservar memoria para el argumento (ruta de la DLL)
	char thData[] = "C:/Users/Zer0/Desktop/dllmain.dll";
	LPVOID dirToArg = VirtualAllocEx(myProc, NULL, strlen(thData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (dirToArg == NULL)
		error("[-] Error reservando memoria para argumento.\n");
	else
		printf("[+] Memoria reservada para argumento (%i bytes).\n", strlen(thData));


	// Escribir la ruta de la DLL en la memoria reservada
	SIZE_T written = 0;
	if (WriteProcessMemory(myProc, dirToArg, (LPVOID)&thData, strlen(thData), &written) == 0)
		error("[-] Error escribiendo memoria.\n");
	else
		printf("[+] Memoria escrita (arg %i bytes).\n", written);
	 //Lanzar un hilo con LoadLibrary
	 //Load the DLL
	 //Load the DLL
	HANDLE rThread = CreateRemoteThread(myProc, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary(L"Kernel32.dll"), "LoadLibraryA"), dirToArg, NULL, NULL);
	if (rThread == NULL)
		error("[-] Error creando el hilo.\n");
	else 
		printf("[+] Hilo creado.\n");
	CloseHandle( rThread );
	
}
