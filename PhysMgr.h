template <typename StrType, typename StrType2>
bool StrICmp(StrType Str, StrType2 InStr, bool Two)
{
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

	if (!Str || !InStr)
		return false;

	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1))
			return true;
	} while (c1 == c2);

	return false;
}

#pragma pack(push, 1)
typedef union CR3_
{
	uintptr_t value;
	struct
	{
		uintptr_t ignored_1 : 3;
		uintptr_t write_through : 1;
		uintptr_t cache_disable : 1;
		uintptr_t ignored_2 : 7;
		uintptr_t pml4_p : 40;
		uintptr_t reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	uintptr_t value;
	void* pointer;

	struct
	{
		uintptr_t offset : 12;
		uintptr_t pt_index : 9;
		uintptr_t pd_index : 9;
		uintptr_t pdpt_index : 9;
		uintptr_t pml4_index : 9;
		uintptr_t reserved : 16;
	};

	struct
	{
		uintptr_t offset : 21;
		uintptr_t pd_index : 9;
		uintptr_t pdpt_index : 9;
		uintptr_t pml4_index : 9;
		uintptr_t reserved : 16;
	} l;
} VIRT_ADDR;

typedef union PML4E_
{
	uintptr_t value;
	struct
	{
		uintptr_t present : 1;
		uintptr_t rw : 1;
		uintptr_t user : 1;
		uintptr_t write_through : 1;
		uintptr_t cache_disable : 1;
		uintptr_t accessed : 1;
		uintptr_t ignored_1 : 1;
		uintptr_t reserved_1 : 1;
		uintptr_t ignored_2 : 4;
		uintptr_t pdpt_p : 40;
		uintptr_t ignored_3 : 11;
		uintptr_t xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	uintptr_t value;
	struct
	{
		uintptr_t present : 1;
		uintptr_t rw : 1;
		uintptr_t user : 1;
		uintptr_t write_through : 1;
		uintptr_t cache_disable : 1;
		uintptr_t accessed : 1;
		uintptr_t dirty : 1;
		uintptr_t page_size : 1;
		uintptr_t ignored_2 : 4;
		uintptr_t pd_p : 40;
		uintptr_t ignored_3 : 11;
		uintptr_t xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	uintptr_t value;
	struct
	{
		uintptr_t present : 1;
		uintptr_t rw : 1;
		uintptr_t user : 1;
		uintptr_t write_through : 1;
		uintptr_t cache_disable : 1;
		uintptr_t accessed : 1;
		uintptr_t dirty : 1;
		uintptr_t page_size : 1;
		uintptr_t global : 1;
		uintptr_t ignored_2 : 3;
		uintptr_t pt_p : 40;
		uintptr_t ignored_3 : 11;
		uintptr_t xd : 1;
	};
} PDE;

typedef union PTE_
{
	uintptr_t value;
	VIRT_ADDR vaddr;
	struct
	{
		uintptr_t present : 1;
		uintptr_t rw : 1;
		uintptr_t user : 1;
		uintptr_t write_through : 1;
		uintptr_t cache_disable : 1;
		uintptr_t accessed : 1;
		uintptr_t dirty : 1;
		uintptr_t pat : 1;
		uintptr_t global : 1;
		uintptr_t ignored_1 : 3;
		uintptr_t page_frame : 40;
		uintptr_t ignored_3 : 11;
		uintptr_t xd : 1;
	};
} PTE;
#pragma pack(pop)

typedef struct _NOPPROCINFO
{
	KDPC DpcTraps[MAXIMUM_PROCESSORS];

	volatile LONG ActiveCores;
	volatile LONG DPCCount;
	volatile LONG IsCodeExecuted;
	volatile void* UpdateEntry;

	ULONG Cores;
	KIRQL SavedIrql;
	KPRIORITY SavedPriority;
}NOPPROCINFO, * PNOPPROCINFO;

VOID DpcRoutine(KDPC* pDpc, void* pContext, void* pArg1, void* pArg2)
{
	KIRQL Irql;
	PNOPPROCINFO Info = (PNOPPROCINFO)pContext;

	UNREFERENCED_PARAMETER(pDpc);
	UNREFERENCED_PARAMETER(pArg1);
	UNREFERENCED_PARAMETER(pArg2);

	InterlockedIncrement(&Info->DPCCount);
	do
	{
		__nop();
	} while (Info->ActiveCores != Info->DPCCount);

	KeRaiseIrql(HIGH_LEVEL, &Irql);
	do
	{
		__nop();
	} while (!Info->IsCodeExecuted);

	if (Info->UpdateEntry)
	{
		//flush cache page entry
		((PTE*)Info->UpdateEntry)->accessed = 0;
		__invlpg((void*)Info->UpdateEntry);

		//flush global cache
		auto v0 = __readcr4();
		__writecr4(v0 ^ 0x80);
		__writecr4(v0);
		v0 = __readcr3();
		__writecr3(v0);

		//flush all core cache
		__wbinvd();
	}
	
	InterlockedDecrement(&Info->DPCCount);
	KeLowerIrql(Irql);
}

VOID InitializeStopProcessors(OUT NOPPROCINFO* Info)
{
	KAFFINITY aff = 0;
	RtlZeroMemory(Info, sizeof(NOPPROCINFO));

	Info->Cores = KeQueryActiveProcessorCount(&aff);

	if (Info->Cores > 1)
	{
		for (ULONG i = 0; i < Info->Cores; i++)
		{
			KeInitializeDpc(&Info->DpcTraps[i], DpcRoutine, Info);
			KeSetImportanceDpc(&Info->DpcTraps[i], LowImportance);
			KeSetTargetProcessorDpc(&Info->DpcTraps[i], (CCHAR)i);
		}
	}
}

VOID StopProcessors(IN NOPPROCINFO* Info)
{
	ULONG CurrentProcessor;
	KAFFINITY ActiveProcessors;

	if (Info->Cores > 1)
	{
		Info->SavedPriority = KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);
		ActiveProcessors = KeQueryActiveProcessors();

		KeRaiseIrql(DISPATCH_LEVEL, &Info->SavedIrql);

		CurrentProcessor = KeGetCurrentProcessorNumber();
		Info->ActiveCores = Info->DPCCount = 0;

		for (ULONG i = 0; i < Info->Cores; i++)
		{
			if ((i != CurrentProcessor) && ((ActiveProcessors & (1ull << i)) != 0))
			{
				InterlockedIncrement(&Info->ActiveCores);
				KeInsertQueueDpc(&Info->DpcTraps[i], &Info, 0);
			}
		}

		KeLowerIrql(Info->SavedIrql);

		do
		{
			__nop();
		} while (Info->ActiveCores != Info->DPCCount);

		KeRaiseIrql(HIGH_LEVEL, &Info->SavedIrql);
	}
	else
		KeRaiseIrql(HIGH_LEVEL, &Info->SavedIrql);
};

VOID StartProcessors(IN NOPPROCINFO* Info)
{
	if (Info->Cores > 1)
	{
		InterlockedExchange(&Info->IsCodeExecuted, 1);
		KeLowerIrql(Info->SavedIrql);

		do
		{
			__nop();
		} while (Info->DPCCount > 0);

		KeSetPriorityThread(KeGetCurrentThread(), Info->SavedPriority);
	}
	else
		KeLowerIrql(Info->SavedIrql);
}

void fastUpdate(void* entry, ULONG64 pfn, bool global, bool unbig)
{
	NOPPROCINFO ff;
	InitializeStopProcessors(&ff);
	ff.UpdateEntry = entry;
	StopProcessors(&ff);

	//fix local cache
	((PTE*)entry)->global = global;
	if (unbig) ((PDE*)entry)->page_size = 0;
	((PTE*)entry)->page_frame = pfn;
	((PTE*)entry)->accessed = 0;
	__invlpg(entry);

	StartProcessors(&ff);
}

void* PfnToVa(uintptr_t pfn) {
	PHYSICAL_ADDRESS phAddr;
	phAddr.QuadPart = pfn << PAGE_SHIFT;
	auto ret = MmGetVirtualForPhysical(phAddr);
	//auto ret2 = MmGetVirtualForPhysical1(phAddr);
	//hp(ret);
	//hp(ret2);
	//sp("^^^^");
	return ret;

}

struct VA_Info
{
	PML4E* PML4;
	PML4E* PML4E;

	PDPTE* PDPT;
	PDPTE* PDPTE;

	PDE* PD;
	PDE* PDE;

	PTE* PT;
	PTE* PTE;
};

typedef struct _PROCESSOR_THREAD_PARAM
{
	KAFFINITY Mask;
	PKSTART_ROUTINE Routine;
	PVOID Param;

} PROCESSOR_THREAD_PARAM,
* PPROCESSOR_THREAD_PARAM;

void NTAPI ProcessorThread(PVOID Param)
{
	PPROCESSOR_THREAD_PARAM ThreadParam = (PPROCESSOR_THREAD_PARAM)Param;

	// bind thread to specific processor
	KeSetSystemAffinityThread(ThreadParam->Mask);

	// execute payload on this processor
	ThreadParam->Routine(ThreadParam->Param);
}

void ForEachProcessor(PKSTART_ROUTINE Routine, PVOID Param)
{
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid IRQL (Must be =PASSIVE_LEVEL)\n");
		return;
	}

	// get bitmask of active processors
	KAFFINITY ActiveProcessors = KeQueryActiveProcessors();

	for (KAFFINITY i = 0; i < sizeof(KAFFINITY) * 8; i++)
	{
		KAFFINITY Mask = 1 << i;
		// check if this processor bit present in mask
		if (ActiveProcessors & Mask)
		{
			HANDLE hThread;
			PROCESSOR_THREAD_PARAM ThreadParam;

			ThreadParam.Mask = Mask;
			ThreadParam.Param = Param;
			ThreadParam.Routine = Routine;

			// create thread for this processor
			NTSTATUS ns = PsCreateSystemThread(
				&hThread,
				THREAD_ALL_ACCESS,
				NULL, NULL, NULL,
				ProcessorThread,
				&ThreadParam
			);
			if (NT_SUCCESS(ns))
			{
				PVOID Thread;
				// get pointer to thread object
				ns = ObReferenceObjectByHandle(
					hThread,
					THREAD_ALL_ACCESS,
					NULL,
					KernelMode,
					&Thread,
					NULL
				);
				if (NT_SUCCESS(ns))
				{
					// waiting for thread termination
					KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
					ObDereferenceObject(Thread);
				}
				else
				{
					//DbgMsg(__FILE__, __LINE__, "ObReferenceObjectByHandle() fails; status: 0x%.8x\n", ns);
				}

				ZwClose(hThread);
			}
			else
			{
				//DbgMsg(__FILE__, __LINE__, "PsCreateSystemThread() fails; status: 0x%.8x\n", ns);
			}
		}
	}
}

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	//get & enum sections
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);
	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		//copy section name
		char SectName[9]; SectName[8] = 0;
		*(ULONG64*)&SectName[0] = *(ULONG64*)&pSect->Name[0];

		//check name
		if (StrICmp(Name, SectName, true))
		{
			//save size
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}

			//ret full sect ptr
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}

	//no section
	return nullptr;
}

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern)
{
	//find pattern utils
	#define InRange(x, a, b) (x >= a && x <= b) 
	#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
	#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

//get sect range
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);
	PUCHAR ModuleEnd = ModuleStart + SectSize;

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');
		if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	//failed
	return nullptr;
}

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))

class Array 
{
public:
	uintptr_t data[64];

	void Init() {
		data[0] = 0;
	}

	bool InList(uintptr_t val, bool AddToList = false)
	{
		//if (!val)
		//	return false;

		for (int i = 0; i < 64; ++i)
		{
			if (!data[i])
			{
				if (AddToList) 
				{
					//hp(val);
					//sp("add");

					data[i] = val;
					data[i + 1] = 0;
				}

				return false;
			}

			if (data[i] == val) {
				return true;
			}
		}
	};

};

class FShadow2
{
private:
	//data
	Array pfns;
	uintptr_t cr3_pfn;

	void AllocApply(void* Entry, void* Ptr, bool UnBig = false, bool Page = false, size_t Size = 0x1000)
	{
		auto rva = FindPatternSect(KBase1, ".text", "48 8D 0D ? ? ? ? 41 8B D6 E8 ? ? ? ? 48 8B");
		typedef __int64(__fastcall* MiInitializePfnFn)(__int64, void*, __int64, __int64);
		auto MiInitializePfn = (MiInitializePfnFn)RVA(FindPatternSect(KBase1, ".text", "E8 ? ? ? ? 48 8B CE 48 8B D3"), 5);
		uintptr_t MiSystemPartition = RVA(rva, 7);
		typedef __int64(__fastcall* MiGetPageFn)(__int64, __int64, __int64);
		auto MiGetPage = (MiGetPageFn)RVA(rva + 10, 5);

		auto pfn = MiGetPage(MiSystemPartition, 0, 8);

		PHYSICAL_ADDRESS phAddr;
		phAddr.QuadPart = pfn << PAGE_SHIFT;

		//copy data
		auto va1 = MmMapIoSpace(phAddr, 0x1000, MmNonCached);
		memcpy(va1, Ptr, 0x1000);
		MmUnmapIoSpace(va1, 0x1000);

		MiInitializePfn(48 * pfn + pfnBase, Entry, 4i64, 4);

		fastUpdate(Entry, pfn, Page ? false : ((PTE*)Entry)->global, UnBig);
	}

	bool QVA(VIRT_ADDR addr, VA_Info& va_info)
	{
		//get pml4e
		va_info.PML4 = (PML4E*)PfnToVa(cr3_pfn);
		va_info.PML4E = &va_info.PML4[addr.pml4_index];
		if (!va_info.PML4 || !va_info.PML4E->present) {
			return false;
		}

		//get pdpte
		va_info.PDPT = (PDPTE*)PfnToVa(va_info.PML4E->pdpt_p);
		va_info.PDPTE = &va_info.PDPT[addr.pdpt_index];
		if (!va_info.PDPT || !va_info.PDPTE->present) {
			return false;
		}

		//get pde
		va_info.PD = (PDE*)PfnToVa(va_info.PDPTE->pd_p);
		va_info.PDE = &va_info.PD[addr.pd_index];
		if (!va_info.PD || !va_info.PDE->present) {
			return false;
		}

		//2Mb page size
		if (va_info.PDE->page_size) {
			va_info.PT = nullptr;
			return true;
		}

		//get pte
		va_info.PT = (PTE*)PfnToVa(va_info.PDE->pt_p);
		va_info.PTE = &va_info.PT[addr.pt_index];
		if (va_info.PT && va_info.PTE->present) {
			//4Kb page size
			return true;
		}

		//error
		return false;
	}

public:
	bool Patch(uintptr_t Addr, PVOID PatchData, ULONG PatchSize)
	{
		auto addr = VIRT_ADDR{ Addr };

		//get va info
		VA_Info va_info;
		int ret = QVA(addr, va_info);
		if (!ret) return false;

		//irql fix
		KIRQL SavedIrql;
		KeRaiseIrql(DISPATCH_LEVEL, &SavedIrql);

		//fixup large pages
		if (!va_info.PT) {
			va_info.PDE->global = false;
		}

		//need new pdpt
		if (!pfns.InList(va_info.PML4E->pdpt_p)) {
			AllocApply(va_info.PML4E, va_info.PDPT);
		}
		
		//need new pde
		if (!pfns.InList(va_info.PDPTE->pd_p)) {
			AllocApply(va_info.PDPTE, va_info.PD);
		}
		
		//need new pt / 2mb page
		if (!pfns.InList(va_info.PDE->pt_p))
		{
			PTE NewPT[512];
			if (!va_info.PT) {
				for (int i = 0; i < 512; i++) {
					NewPT[i].value = 0;
					NewPT[i].present = true;
					NewPT[i].rw = va_info.PDE->rw;
					NewPT[i].user = va_info.PDE->user;
					NewPT[i].xd = va_info.PDE->xd;
					NewPT[i].global = va_info.PDE->global;
					NewPT[i].page_frame = va_info.PDE->pt_p + i;
				}
			}

			//BIG alloc
			AllocApply(va_info.PDE, va_info.PT ? va_info.PT : NewPT, 1, 0);
			if (!va_info.PT) {
				KeLowerIrql(SavedIrql);
				return Patch(Addr, PatchData, PatchSize);
			}
		}

		//need 4kb page
		if (va_info.PT && !pfns.InList(va_info.PTE->page_frame))
		{
			//4kb page align
			addr.offset = 0;

			//alloc
			AllocApply(va_info.PTE, addr.pointer, 0, 1);
		}

		//patch
		ULONGLONG cr0 = __readcr0();
		__writecr0(cr0 & 0xFFFEFFFF);
		memcpy((void*)Addr, PatchData, PatchSize);
		__writecr0(cr0);

		//irql fix
		KeLowerIrql(SavedIrql);

		//okay hehe...))
		return true;
	}

	void Init(uintptr_t CR3) {
		pfns.Init();
		cr3_pfn = PTE_CR3{ CR3 }.pml4_p;
	}
};