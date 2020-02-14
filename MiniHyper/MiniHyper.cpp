#include <Windows.h>
#include <iostream>
#include <WinHvPlatform.h>
#include <WinHvEmulation.h>
#pragma comment(lib, "winhvplatform.lib")
#pragma comment(lib, "winhvemulation.lib")
#include "def.h"
using namespace std;

#define PS_LIMIT (0x200000)
#define KERNEL_STACK_SIZE (0x4000)
#define MAX_KERNEL_SIZE (PS_LIMIT - 0x5000 - KERNEL_STACK_SIZE)
#define MEM_SIZE (PS_LIMIT*2)



WHV_REGISTER_NAME regNames[] = {
	WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRbx,
	WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterRsi, WHvX64RegisterRdi,
	WHvX64RegisterR8, WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
	WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
	WHvX64RegisterRip, WHvX64RegisterRflags,
	WHvX64RegisterEs, WHvX64RegisterCs, WHvX64RegisterSs, WHvX64RegisterDs,
	WHvX64RegisterFs, WHvX64RegisterGs,
	WHvX64RegisterGdtr, 
	WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
	WHvX64RegisterCr8,
	WHvX64RegisterEfer, WHvX64RegisterLstar, WHvRegisterPendingInterruption
};
#define RegGdtr 24
#define RegCr0 25
#define RegCr2 26
#define RegCr3 27
#define RegCr4 28
#define RegCr8 29
#define RegEfer 30

typedef struct virtualProcessor {
	UINT vpIndex;
	WHV_REGISTER_VALUE registers[RTL_NUMBER_OF(regNames)];
	WHV_RUN_VP_EXIT_CONTEXT ExitContext;
}virtualProcessor;

typedef struct _Partition {
	WHV_PARTITION_HANDLE hPartition;
	virtualProcessor vp;
	LPVOID * source;
	WHV_GUEST_PHYSICAL_ADDRESS GPA;
}_Partition;

virtualProcessor vp;
_Partition partition;
void dumpReg() {
	WHvGetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		regNames,
		RTL_NUMBER_OF(regNames),
		vp.registers
	);
	cout << "----------------------------------------\n";
	cout.setf(ios::hex, ios::basefield);
	cout.setf(ios::showbase);
	cout << "Rax" << " = " << vp.registers[0].Reg64 << "\t";
	cout << "Rcx" << " = " << vp.registers[1].Reg64 << "\n";
	cout << "Rdx" << " = " << vp.registers[2].Reg64 << "\t";
	cout << "Rbx" << " = " << vp.registers[3].Reg64 << "\n";
	cout << "Rsp" << " = " << vp.registers[4].Reg64 << "\t";
	cout << "Rbp" << " = " << vp.registers[5].Reg64 << "\n";
	cout << "Rsi" << " = " << vp.registers[6].Reg64 << "\t";
	cout << "Rdi" << " = " << vp.registers[7].Reg64 << "\n";
	cout << "R8" << " = " << vp.registers[8].Reg64 << "\t";
	cout << "R9" << " = " << vp.registers[9].Reg64 << "\n";
	cout << "R10" << " = " << vp.registers[10].Reg64 << "\t";
	cout << "R11" << " = " << vp.registers[11].Reg64 << "\n";
	cout << "R12" << " = " << vp.registers[12].Reg64 << "\t";
	cout << "R13" << " = " << vp.registers[13].Reg64 << "\n";
	cout << "R14" << " = " << vp.registers[14].Reg64 << "\t";
	cout << "R15" << " = " << vp.registers[15].Reg64 << "\n";
	cout << "Rip" << " = " << vp.registers[16].Reg64 << "\t";
	cout << "Rflags" << " = " << vp.registers[17].Reg64 << "\n";
	cout << "Es" << " = " << vp.registers[WHvX64RegisterEs].Reg64 << "\t";

	cout << "Cs.Base" << " = " << vp.registers[WHvX64RegisterCs].Segment.Base << "\t";
	cout << "Cs.Limit" << " = " << vp.registers[WHvX64RegisterCs].Segment.Limit << "\t";
	cout << "Cs.Selector" << " = " << vp.registers[WHvX64RegisterCs].Segment.Selector << "\t";
	cout << "Cs.Present" << " = " << vp.registers[WHvX64RegisterCs].Segment.Present << "\t";
	cout << "Cs.SegmentType" << " = " << vp.registers[WHvX64RegisterCs].Segment.SegmentType << "\t";
	cout << "Cs.Default" << " = " << vp.registers[WHvX64RegisterCs].Segment.Default << "\t";
	cout << "Cs.Default" << " = " << vp.registers[WHvX64RegisterCs].Segment.Granularity << "\t";
	cout << "Cs.NonSystemSegment" << " = " << vp.registers[WHvX64RegisterCs].Segment.NonSystemSegment << "\t";

	cout << "Ss" << " = " << vp.registers[WHvX64RegisterSs].Segment.Base << "\n";
	cout << "Ds" << " = " << vp.registers[WHvX64RegisterDs].Segment.SegmentType << "\t";
	cout << "Fs" << " = " << vp.registers[WHvX64RegisterFs].Reg64 << "\t";
	cout << "Gs" << " = " << vp.registers[WHvX64RegisterGs].Reg64 << "\n";
	cout << "Cr0" << " = " << vp.registers[RegCr0].Reg64 << "\t";
	cout << "Cr2" << " = " << vp.registers[RegCr2].Reg64 << "\t";
	cout << "Cr3" << " = " << vp.registers[RegCr3].Reg64 << "\n";
	cout << "Cr4" << " = " << vp.registers[RegCr4].Reg64 << "\t";
	cout << "Cr8" << " = " << vp.registers[RegCr8].Reg64 << "\n";
	cout << "GDTR" << " = " << vp.registers[RegGdtr].Reg64 << "\n";
	cout << "Efer" << " = " << vp.registers[RegEfer].Reg64 << "\n";
	cout << "----------------------------------------\n";
	cout.unsetf(ios::hex);
}

auto deletePartition() {
	WHvDeleteVirtualProcessor(partition.hPartition, partition.vp.vpIndex);
	WHvDeletePartition(partition.hPartition);
}

auto ioPortCallback(VOID* Context, WHV_EMULATOR_IO_ACCESS_INFO* IoAccess) {
	//if(IoAccess->Direction == )
	cout << (char)IoAccess->Data;
	WHV_TRANSLATE_GVA_RESULT translateCode;
	return S_OK;
}

auto memoryCallback(VOID* Context, WHV_EMULATOR_MEMORY_ACCESS_INFO* MemoryAccess) {
	cout << "Memory Callback\n";
	return S_OK;
}

auto getVirtualProcessorRegisters(VOID* Context, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, WHV_REGISTER_VALUE* RegisterValues) {
	cout << "Get registers callback\n";
	HRESULT result = WHvGetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		RegisterNames,
		RegisterCount,
		RegisterValues
	);

	return result;
}

auto translateGpaCallback(VOID* Context, WHV_GUEST_VIRTUAL_ADDRESS GvaPage, WHV_TRANSLATE_GVA_FLAGS TranslateFlags, WHV_TRANSLATE_GVA_RESULT_CODE* TranslationResult, WHV_GUEST_PHYSICAL_ADDRESS* GpaPage) {
	cout << "Translate Gva Callback\n";
	WHV_TRANSLATE_GVA_RESULT translateCode;
	HRESULT result = WHvTranslateGva(partition.hPartition, vp.vpIndex, GvaPage, TranslateFlags, &translateCode, GpaPage);
	TranslationResult = &translateCode.ResultCode;

	return result;
}

auto setVirtualProcessorRegisters(VOID* Context, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, const WHV_REGISTER_VALUE* RegisterValues) {
	HRESULT result = WHvSetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		RegisterNames,
		RegisterCount,
		RegisterValues
	);

	return result;
}

WHV_EMULATOR_HANDLE emulator;
WHV_EMULATOR_CALLBACKS callbacks = {
	0x1000,
	0,
	&ioPortCallback,
	&memoryCallback,
	&getVirtualProcessorRegisters,
	&setVirtualProcessorRegisters,
	&translateGpaCallback

};

auto handleIo(const WHV_RUN_VP_EXIT_CONTEXT * exitContext) {
	HRESULT result = WHvEmulatorCreateEmulator(
		&callbacks,
		&emulator
	);

	if (result < 0) {
		cerr << "CreateEmulation failed\n";
		deletePartition();
	}

	VOID * context = NULL;
	WHV_EMULATOR_STATUS emuReturnStatus;
	WHvEmulatorTryIoEmulation(
		emulator,
		context,
		&exitContext->VpContext,
		&exitContext->IoPortAccess,
		&emuReturnStatus
	);
	if (emuReturnStatus.EmulationSuccessful != true) {
		cerr << "Emulation not successful\n";
	}
	WHvEmulatorDestroyEmulator(&emulator);
}

auto vmExitHandler(WHV_RUN_VP_EXIT_CONTEXT * ExitContext) {
	auto ER = ExitContext->ExitReason;
	switch (ER) {
	case WHvRunVpExitReasonNone:
		cerr << "Error : WHvRunVpExitReasonNone\n";
		return ER;
	case WHvRunVpExitReasonMemoryAccess:
		cerr << "Error : WHvRunVpExitReasonMemoryAccess\n";
		return ER;
	case WHvRunVpExitReasonX64IoPortAccess:
		cerr << "Error : WHvRunVpExitReasonX64IoPortAccess\n";
		handleIo(ExitContext);
		return ER;
	case WHvRunVpExitReasonUnrecoverableException:
		cerr << "Error : WHvRunVpExitReasonUnrecoverableException\n";
		return ER;
	case WHvRunVpExitReasonInvalidVpRegisterValue:
		cerr << "Error : WHvRunVpExitReasonInvalidVpRegisterValue\n";
		return ER;
	case WHvRunVpExitReasonUnsupportedFeature:
		cerr << "Error : WHvRunVpExitReasonUnsupportedFeature\n";
		return ER;
	case WHvRunVpExitReasonX64InterruptWindow:
		cerr << "Error : WHvRunVpExitReasonX64InterruptWindow\n";
		return ER;
	case WHvRunVpExitReasonX64Halt:
		cerr << "Error : WHvRunVpExitReasonX64Halt\n";
		return ER;
	default: return ER;
	}
}

auto checkCapability() {
	WHV_CAPABILITY Capability;

	WHV_CAPABILITY_CODE CapabilityCode = WHvCapabilityCodeHypervisorPresent;

	HRESULT result = WHvGetCapability(
		CapabilityCode,
		&Capability,
		sizeof(Capability),
		NULL
	);

	if (result != S_OK || Capability.HypervisorPresent != TRUE) {
		cerr << "Windows Hypervisor platform not enabled.\n";
		exit(0);
	}
}

auto setupPartition() {
	// Create a partition object
	if (WHvCreatePartition(&partition.hPartition) < 0) {
		cerr << "Create Partition failed\n";
		exit(0);
	}

	// Setup properties of partition, specify one virtual processor
	WHV_PARTITION_PROPERTY Property;
	ZeroMemory(&Property, sizeof(Property));
	Property.ProcessorCount = 1;

	HRESULT result = WHvSetPartitionProperty(
		partition.hPartition,
		WHvPartitionPropertyCodeProcessorCount,
		&Property,
		sizeof(Property)
	);
	if (result != S_OK) {
		cerr << "Partion property setup failed\n";
		exit(0);
	}

	result = WHvSetupPartition(partition.hPartition);
	if (result < 0) {
		cerr << "Partition setup failed";
	}
}

auto setupLongMode() {
	WHvGetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		regNames,
		RTL_NUMBER_OF(regNames),
		vp.registers
	);

	UINT64 * mem = (UINT64 *)partition.source;

	UINT64 PML4T_addr = 0x1000;
	UINT64 *pml4t = mem + PML4T_addr;

	UINT64 PDPT_addr = PML4T_addr + 0x1000;
	UINT64 *pdpt = mem + PDPT_addr;

	UINT64 PDT_addr = PDPT_addr + 0x1000;
	UINT64 *pdt = mem + PDT_addr;

	UINT64 PT_addr = PDT_addr + 0x1000;
	UINT64 *pt = mem + PT_addr;

	pml4t[0] = 3 | PDPT_addr | PDE64_USER; // PDE64_PRESENT | PDE64_RW | pdpt_addr
	pdpt[0] = 3 | PDT_addr | PDE64_USER; // PDE64_PRESENT | PDE64_RW | pd_addr
	pdt[0] = 0 | 3 ; // PDE64_PRESENT | PDE64_RW | PDE64_PS


	/*
	UINT64 GDT_addr = 0x5000;
	UINT64 * gdt = mem + GDT_addr;
	gdt[0] = {.base=0, .limit=0, .type=0};                     // Selector 0x00 cannot be used
	gdt[1] = {.base=0, .limit=0xffffffff, .type=0x9A};         // Selector 0x08 will be our code
	gdt[2] = {.base=0, .limit=0xffffffff, .type=0x92};         // Selector 0x10 will be our data
	*/

	vp.registers[WHvX64RegisterCs].Segment.Base = 0x0;
	vp.registers[WHvX64RegisterCs].Segment.Selector = 0x0;
	vp.registers[RegGdtr].Reg64 = 0x0;
	vp.registers[RegCr0].Reg64 |= CR0_PE;
/*
	UINT64 x = PDE64_PRESENT | PDE64_RW;
	int i = 0;
	while (i < 512) {
		pt[i] = (UINT64)x;
		i++;
		x += 0x1000;
	}
*/


/*
vp.registers[RegCr4].Reg64 = CR4_PAE;
vp.registers[RegCr4].Reg64 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
vp.registers[RegCr0].Reg64 |= CR0_PG;

	vp.registers[RegCr3].Reg64 = PML4T_addr;
	//vp.registers[RegCr0].Reg64 |= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM ;
	//vp.registers[RegCr0].Reg64 = 0x80050033;
	vp.registers[RegCr4].Reg64 = 0x6E8;
	vp.registers[RegEfer].Reg64 = EFER_LMA | EFER_LME | EFER_SCE;

	//vp.registers[WHvX64RegisterRflags].Reg64 |= 0x02;

	vp.registers[WHvX64RegisterCs].Segment.DescriptorPrivilegeLevel = 0;
    vp.registers[WHvX64RegisterCs].Segment.Long = 1;
    vp.registers[WHvX64RegisterCs].Segment.Base = 0;
    vp.registers[WHvX64RegisterCs].Segment.Selector = 0x33;

    vp.registers[WHvX64RegisterSs].Segment.Selector = 0x2B;
    vp.registers[WHvX64RegisterSs].Segment.DescriptorPrivilegeLevel = 0;
    vp.registers[WHvX64RegisterDs] = vp.registers[WHvX64RegisterSs];
    vp.registers[WHvX64RegisterEs] = vp.registers[WHvX64RegisterSs];
    vp.registers[WHvX64RegisterGs] = vp.registers[WHvX64RegisterSs];
*/

	HRESULT result = WHvSetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		regNames,
		RTL_NUMBER_OF(regNames),
		vp.registers
	);

	if (result < 0) {
		cerr << "Setting Register failed \n";
		deletePartition();
		exit(0);
	}
}

int main() {
	checkCapability();
	setupPartition();

	// source address is the address in host process,
	// the guest physical address is the where the memory is reflected in the vm
	auto source = VirtualAlloc(NULL, MEM_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (source == NULL) {
		cerr << "allocation failed\n";
		WHvDeletePartition(partition.hPartition);
		exit(0);
	}
	ZeroMemory(source, MEM_SIZE);

	partition.GPA = 0x00000;
	partition.source = (LPVOID*)source;

	HRESULT result = WHvMapGpaRange(
		partition.hPartition,
		partition.source,
		partition.GPA,
		PS_LIMIT * 2,
		WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute
	);
	if (result < 0) {
		cerr << "WHvMapGpaRange failed\n";
		WHvDeletePartition(partition.hPartition);
		exit(0);
	}

	vp.vpIndex = 0;
	result = WHvCreateVirtualProcessor(partition.hPartition, vp.vpIndex, 0);
	if (result < 0) {
		cerr << "Create processor failed\n";
		WHvDeletePartition(partition.hPartition);
		exit(0);
	}

	ZeroMemory(vp.registers, sizeof(vp.registers));
	setupLongMode();

	unsigned char code[] = "\x0f\x20\xc0\x83\xc8\x01\x0f\x22\xc0\xeb\xf9\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xbb\x37\x13\x37";
	//unsigned char code[] = "\xb8\x10\x00\x00\x00\xbb\x20\x00\x00\x00\xb9\x30\x00\x00\x00\xf4";
	//unsigned char code[] = "\fa\xb8\x10\x00\xbb\x20\x00\xb9\x30\x00\xf4";
	//unsigned char code[] = "\xe8\x0f\x00\x00\x00\x90\x90\x90\x90\x90\xb8\x37\x13\x37\x13\xf4";

	CopyMemory((LPVOID*)source+0x0000, code, sizeof(code));
	vp.registers[WHvX64RegisterRip].Reg64 = (UINT64)partition.GPA+0x0000;
	vp.registers[WHvX64RegisterRflags].Reg64 |= 0x2;

	result = WHvSetVirtualProcessorRegisters(
		partition.hPartition,
		vp.vpIndex,
		regNames,
		RTL_NUMBER_OF(regNames),
		vp.registers
	);

	if (result < 0) {
		cerr << "Setting Register failed\n";
		deletePartition();
		exit(0);
	}
	dumpReg();

	HRESULT ER = -1;
	while (ER != WHvRunVpExitReasonX64Halt) {
		WHvRunVirtualProcessor(
			partition.hPartition,
			vp.vpIndex,
			&vp.ExitContext,
			sizeof(vp.ExitContext)
		);
		ER = vmExitHandler(&vp.ExitContext);
	}
	dumpReg();

	deletePartition();
	return 0;
}