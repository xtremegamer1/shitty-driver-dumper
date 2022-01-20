#pragma once
#include "definitions.h"

NTSTATUS find_system_module_info_by_path(const char* module_path, _Out_ PRTL_PROCESS_MODULE_INFORMATION return_info);
NTSTATUS find_system_module_info_by_path2(const wchar_t* module_path, _Out_ PLDR_DATA_TABLE_ENTRY return_info);
NTSTATUS find_system_module_info_by_name(const char* module_name, _Out_ PRTL_PROCESS_MODULE_INFORMATION return_info);
NTSTATUS dumpModInfo(PVOID moduleBase);
NTSTATUS dumpModules();