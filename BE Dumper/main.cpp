#include "memory.h"

#define SECONDS(s) (10'000'000 * s)

NTSTATUS dumpModules();
void Timer_Thread(PVOID StartContext);

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	HANDLE threadHandle;

	PsCreateSystemThread(
		&threadHandle,
		DELETE,
		NULL,
		NULL,
		NULL,
		(PKSTART_ROUTINE)Timer_Thread,
		NULL
	);

	ZwClose(threadHandle);

	return STATUS_SUCCESS;
}

//DriverEntry initializes a thread with this function then returns immediately
void Timer_Thread(PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	//ZwCreateFile setup
	OBJECT_ATTRIBUTES fileAttrib;
	UNICODE_STRING fileObjName;
	IO_STATUS_BLOCK iostatusblock;
	HANDLE dumpFileH;

	//Where you want to write the dump to 
	RtlInitUnicodeString(&fileObjName,
		L"\\DosDevices\\C:\\YourDump.sys");

	InitializeObjectAttributes(&fileAttrib, &fileObjName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//Create the file that contains the dump
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

	RTL_PROCESS_MODULE_INFORMATION modInfo;

	//Timer setup
	KTIMER timer;
	KeInitializeTimer(&timer);
	LARGE_INTEGER waitTime;
	waitTime.QuadPart = -SECONDS(1);

	//This loop runs every second checking for the driver, the idea being that
	//I start the driver then launch Battleye, never troubling myself with io
	while (true)
	{
		KeSetTimer(&timer, waitTime, NULL);
		//Waiting for driver...
		KeWaitForSingleObject(&timer, Executive, KernelMode, TRUE, nullptr);
		//find_system_module_info_by_path calls ZwQuerySystemInformation and iterates through the module list
		//Put the driver you want to dump here
		if (NT_SUCCESS(find_system_module_info_by_name("yourdriver.sys", &modInfo)))
		{
			break;
		}
	}

	dumpModules();

	dumpModInfo(modInfo.ImageBase);
	IMAGE_DOS_HEADER dos_header = *(PIMAGE_DOS_HEADER)modInfo.ImageBase;

	if (dos_header.e_magic != 0x5A4D)
	{
		ZwWriteFile(
			dumpFileH,
			NULL, NULL, NULL,
			&iostatusblock,
			"Failed",
			7,
			NULL,
			NULL
		);
		ZwClose(dumpFileH);
		return;
	}

	IMAGE_NT_HEADERS64 nt_header =
		*(PIMAGE_NT_HEADERS64)((ULONGLONG)modInfo.ImageBase + dos_header.e_lfanew);

	PIMAGE_SECTION_HEADER pSectionArray =
		(PIMAGE_SECTION_HEADER)((ULONGLONG)modInfo.ImageBase + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS64));

	size_t headers_length = nt_header.OptionalHeader.SizeOfHeaders;

	ZwWriteFile(
		dumpFileH,
		NULL, NULL, NULL,
		&iostatusblock,
		modInfo.ImageBase,
		(ULONG)headers_length,
		NULL,
		NULL
	);

	for (unsigned int i = 0; i < nt_header.FileHeader.NumberOfSections; i++)
	{
		//Check if section is discardable
		if (!(pSectionArray[i].Characteristics & 0x02000000))
		{
			ZwWriteFile(
				dumpFileH,
				NULL, NULL, NULL,
				&iostatusblock,
				(PVOID)((ULONGLONG)modInfo.ImageBase + pSectionArray[i].VirtualAddress),
				pSectionArray[i].Misc.VirtualSize,
				NULL,
				NULL
			);
		}
	}

	ZwClose(dumpFileH);

	return;
} 

/*According to the driver: 
Image Size: 3817472
Image Base: FFFFF80436400000*/

/*According to the bugcheck:
* ImageSize: 3817472
* Image Base: FFFFF80436400000
*/