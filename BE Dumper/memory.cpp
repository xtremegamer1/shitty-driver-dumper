#include "definitions.h"
#include <stdlib.h>

NTSTATUS find_system_module_info_by_path(const char* module_path, _Out_ PRTL_PROCESS_MODULE_INFORMATION return_info)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'nigs');

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return status;

	//Initialize "module" with the value of the pointer to the 
	//module array stored in the return struct of 
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_path) == 0)
		{
			*return_info = module[i];
			if (modules)
				ExFreePoolWithTag(modules, NULL);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS find_system_module_info_by_name(const char* module_name, _Out_ PRTL_PROCESS_MODULE_INFORMATION return_info)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'nigs');

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return status;

	//Initialize "module" with the value of the pointer to the 
	//module array stored in the return struct of 
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
		{
			*return_info = module[i];
			if (modules)
				ExFreePoolWithTag(modules, NULL);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS find_system_module_info_by_path2(const wchar_t* module_path, _Out_ PLDR_DATA_TABLE_ENTRY return_info)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"PsLoadedModuleList");
	PLIST_ENTRY module_list = (PLIST_ENTRY)MmGetSystemRoutineAddress(&name);

	if (!module_list)
		return STATUS_UNSUCCESSFUL;

	UNICODE_STRING path;
	RtlInitUnicodeString(&path, module_path);

	for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlEqualUnicodeString(&entry->FullDllName, &path, TRUE))
		{
			*return_info = *entry;
			return STATUS_SUCCESS;
		}
	}
	
	return STATUS_UNSUCCESSFUL;
}

#define FWRITE(file, string, length) ZwWriteFile((file), NULL, NULL, NULL, &iostatusblock, (string), (length), NULL, NULL);

NTSTATUS dumpModInfo(PVOID moduleBase)
{

	OBJECT_ATTRIBUTES fileAttrib;
	UNICODE_STRING fileObjName;
	IO_STATUS_BLOCK iostatusblock;

	RtlInitUnicodeString(&fileObjName,
		L"\\DosDevices\\C:\\Users\\Richard\\Documents\\Hacking\\dumps\\DumpInfo.txt");

	InitializeObjectAttributes(&fileAttrib, &fileObjName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE hInfoFile;

	LARGE_INTEGER current_time;
	KeQuerySystemTime(&current_time);

	ZwCreateFile(
		&hInfoFile,
		GENERIC_WRITE,
		&fileAttrib,
		&iostatusblock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	char writeBuffer[256]{};

	sprintf(writeBuffer, "Current System Time is: %lld (hundreds of nanoseconds since January 1st, 1601)\n", current_time.QuadPart);
	FWRITE(hInfoFile, writeBuffer, (ULONG)strlen((const char*)writeBuffer));
	memset(writeBuffer, 0x00, 256);

	sprintf(writeBuffer, "Module Base: %p\n", moduleBase);
	FWRITE(hInfoFile, writeBuffer, (ULONG)strlen((const char*)writeBuffer));
	memset(writeBuffer, 0x00, 256);

	ZwClose(hInfoFile);
	return STATUS_SUCCESS;
}

NTSTATUS dumpModules()
{
	//Dump all module names and write it to a file

	OBJECT_ATTRIBUTES fileAttrib;
	UNICODE_STRING fileObjName;
	IO_STATUS_BLOCK iostatusblock;

	RtlInitUnicodeString(&fileObjName,
		L"\\DosDevices\\C:\\Users\\Richard\\Documents\\ActiveDrivers.txt");

	InitializeObjectAttributes(&fileAttrib, &fileObjName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE dumpFileH;

	ZwCreateFile(
		&dumpFileH,
		GENERIC_WRITE,
		&fileAttrib,
		&iostatusblock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	char newline{ '\n' };

	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'nigs');

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	//Initialize "module" with the value of the pointer to the 
	//module array stored in the return struct of ZwQuerySystemInformation
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		ZwWriteFile(
			dumpFileH,
			NULL, NULL, NULL,
			&iostatusblock,
			(PVOID) & module[i].FullPathName,
			(ULONG)strlen((const char*)&module[i].FullPathName),
			NULL,
			NULL);
		ZwWriteFile(
			dumpFileH,
			NULL, NULL, NULL,
			&iostatusblock,
			(PVOID)&newline,
			1,
			NULL,
			NULL);
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (dumpFileH)
		ZwClose(dumpFileH);

	return STATUS_SUCCESS;
}
