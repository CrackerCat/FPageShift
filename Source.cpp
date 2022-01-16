#include <ntifs.h>
#include <intrin.h>
#include <windef.h>

#define wsp(a) DbgPrintEx(0, 0, "\nFACE WSTR: %ws\n", (a))
#define hp(a) DbgPrintEx(0, 0, "\nFACE HEX: 0x%p\n", (a))
#define sp(a) DbgPrintEx(0, 0, "\nFACE STR: %s\n", (a))
#define dp(a) DbgPrintEx(0, 0, "\nFACE DEC: %d\n", (a))

PVOID KBase1;

uintptr_t pfnBase;
uintptr_t PTE_Base;
uintptr_t PDE_Base;

#include "Internals.h"
#include "PhysMgr.h"


void KFree(PVOID Ptr) {
	ExFreePoolWithTag(Ptr, 'KgxD');
}

PVOID KAlloc(ULONG Size) {
	PVOID Buff = ExAllocatePoolWithTag(NonPagedPoolNx, Size, 'KgxD');
	memset(Buff, 0, Size); return Buff;
}

PVOID NQSI(SYSTEM_INFORMATION_CLASS Class)
{
	//get alloc size
	NewTry: ULONG ReqSize = 0;
	ZwQuerySystemInformation(Class, nullptr, ReqSize, &ReqSize);
	if (!ReqSize) goto NewTry;

	//call QuerySystemInfo
	PVOID pInfo = KAlloc(ReqSize);
	if (!NT_SUCCESS(ZwQuerySystemInformation(Class, pInfo, ReqSize, &ReqSize))) {
		KFree(pInfo); goto NewTry;
	}

	//ret buff
	return pInfo;
}

PEPROCESS AttachToProcess(HANDLE PID)
{
	//get eprocess
	PEPROCESS Process = nullptr;
	if (PsLookupProcessByProcessId(PID, &Process) || !Process)
		return nullptr;

	//take process lock
	if (PsAcquireProcessExitSynchronization(Process))
	{
		//process lock failed
		ObfDereferenceObject(Process);
		return nullptr;
	}

	//attach to process
	KeAttachProcess(Process);
	return Process;
}

void DetachFromProcess(PEPROCESS Process)
{
	//check valid process
	if (Process != nullptr)
	{
		//de-attach to process
		KeDetachProcess();

		//cleanup & process unlock
		ObfDereferenceObject(Process);
		PsReleaseProcessExitSynchronization(Process);
	}
}

PEPROCESS GetProcess(const char* ProcName/*, const char* ModName, PVOID* WaitModBase*/)
{
	//get process list
	PEPROCESS EProc = nullptr;
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation), pInfoCur = pInfo;

	while (true)
	{
		//get process name
		const wchar_t* ProcessName = pInfoCur->ImageName.Buffer;
		if (MmIsAddressValid((PVOID)ProcessName))
		{
			//check process name
			if (StrICmp(ProcName, ProcessName, true))
			{
				//attach to process
				PEPROCESS Process = AttachToProcess(pInfoCur->UniqueProcessId);
				if (Process != nullptr)
				{
					//check wait module
					//PVOID ModBase = GetUserModuleBase(Process, ModName);
					//if (ModBase)
					{
						//save modbase
						//if (WaitModBase)
						//	*WaitModBase = ModBase;

						//save eprocess
						EProc = Process;
						break;
					}

					//failed, no wait module
					DetachFromProcess(Process);
				}
			}
		}

		//goto next process entry
		if (!pInfoCur->NextEntryOffset) break;
		pInfoCur = (PSYSTEM_PROCESS_INFO)((ULONG64)pInfoCur + pInfoCur->NextEntryOffset);
	}

	//cleanup
	KFree(pInfo);
	return EProc;
}

FShadow2 gg;


void Sleep(LONG64 MSec) {
	LARGE_INTEGER Delay; Delay.QuadPart = -MSec * 10000;
	KeDelayExecutionThread(KernelMode, false, &Delay);
}
bool KeAreInterruptsEnabled() {
	return (__readeflags() & 0x200) != 0;
}


#pragma optimize("", off)
void init_thread()
{
	
	

	auto proc = GetProcess("explorer.exe");

	auto ff = RtlWalkFrameChain;
	//auto ff2 = (ULONG64)RtlWalkFrameChain + 1;
	auto ff2 = ExAllocatePool(NonPagedPool, 0x1000);
	*(unsigned char*)ff2 = 0x77;
	auto ff3 = 0xfffff803465f1000;// ExAllocatePool(NonPagedPool, 0x1000);
	auto ff4 = 0xfffff803465f1051;// ExAllocatePool(NonPagedPool, 0x1000);
	auto ff5 = 0xfffff803465f2000;// ExAllocatePool(NonPagedPool, 0x1000);
	auto ff6 = 0xfffff803462b1010;// ExAllocatePool(NonPagedPool, 0x1000);


	//*(ULONG*)ff = 0xC1;

	auto dirbase = *(ULONG64*)((ULONG64)proc + 0x28);
	///gg.Init(dirbase);

	

	hp(ff);
	hp(ff2);
	hp(ff3);
	hp(ff4);
	hp(ff5);
	hp(ff6);

	unsigned char ff3334[] = { 0x48, 0x8B, 0xC4 };
	unsigned char ff333[] = { 0x48, 0xC7, 0xC0, 0xCE, 0xFA, 0x00, 0x00, 0xC3 };
	unsigned char ff33 = 0xC3;

	gg.Init(dirbase);
	dp(gg.Patch((uintptr_t)ff, &ff33, sizeof(ff33)));
	dp(gg.Patch((uintptr_t)ff2, &ff33, sizeof(ff33)));
	dp(gg.Patch((uintptr_t)ff3, &ff33, sizeof(ff33)));
	dp(gg.Patch((uintptr_t)ff4, &ff33, sizeof(ff33)));
	dp(gg.Patch((uintptr_t)ff5, &ff33, sizeof(ff33)));
	dp(gg.Patch((uintptr_t)ff6, &ff33, sizeof(ff33)));

	Sleep(1000);

	sp("p *****");
	hp(*(unsigned char*)ff); 
	hp(*(unsigned char*)ff2);
	hp(*(unsigned char*)ff3);
	hp(*(unsigned char*)ff4);
	hp(*(unsigned char*)ff5);
	hp(*(unsigned char*)ff6);

	DetachFromProcess(proc);

	Sleep(1000);

	sp("un *****");
	hp(*(unsigned char*)ff);
	hp(*(unsigned char*)ff2);
	hp(*(unsigned char*)ff3);
	hp(*(unsigned char*)ff4);
	hp(*(unsigned char*)ff5);
	hp(*(unsigned char*)ff6);

}
#pragma optimize("", on)


NTSTATUS DriverEntry(PVOID a1, PVOID KBase)
{
	KBase1 = KBase;
	pfnBase = *(ULONG64*)(FindPatternSect(KBase1, ".text", "48 B8 ? ? ? ? ? ? ? ? 48 8B 04 D0 48 C1 E0") + 2) - 8;

	HANDLE init_thread_handle;
	PsCreateSystemThread(&init_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)init_thread, NULL);
	ZwClose(init_thread_handle);
	
	
	return STATUS_SUCCESS;
}