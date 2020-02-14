#pragma once

// CR0 bits 
#define CR0_PE 1u					// Protected Mode Enable	
#define CR0_MP (1u << 1)			// Monitor co-processor	
#define CR0_EM (1u << 2)			// Emulation
#define CR0_TS (1u << 3)			// Task switched	
#define CR0_ET (1u << 4)			// Extension type	
#define CR0_NE (1u << 5)			// Numeric error	
#define CR0_WP (1u << 16)			// Write protect	
#define CR0_AM (1u << 18)			// Alignment mask	
#define CR0_NW (1u << 29)			// Not-write through	
#define CR0_CD (1u << 30)			// Cache disable	
#define CR0_PG (1u << 31)			// Paging

// CR4 bits 
#define CR4_VME 1u					// Virtual 8086 Mode Extensions	
#define CR4_PVI (1u << 1)			// Protected-mode Virtual Interrupts	
#define CR4_TSD (1u << 2)			// Time Stamp Disable	
#define CR4_DE (1u << 3)			// Debugging Extensions	
#define CR4_PSE (1u << 4)			// Page Size Extension
#define CR4_PAE (1u << 5)			// PAE (Physical Address Extension)
#define CR4_MCE (1u << 6)			// Machine Check Exception	
#define CR4_PGE (1u << 7)			// Page Global Enabled	
#define CR4_PCE (1u << 8)			// Performance-Monitoring Counter enable	
#define CR4_OSFXSR (1u << 9)		// Operating system support for FXSAVE and FXRSTOR instructions	
#define CR4_OSXMMEXCPT (1u << 10)   // Operating System Support for Unmasked SIMD Floating-Point Exceptions	
#define CR4_UMIP (1u << 11)			// User-Mode Instruction Prevention	
#define CR4_VMXE (1u << 13)			// Virtual Machine Extensions Enable	
#define CR4_SMXE (1u << 14)			// Safer Mode Extensions Enable	
#define CR4_FSGSBASE (1u << 16)		// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
#define CR4_PCIDE (1u << 17)		// PCID Enable	
#define CR4_OSXSAVE (1u << 18)		// XSAVE and Processor Extended States Enable	
#define CR4_SMEP (1u << 20)			// SMEP (Supervisor Mode Execution Protection Enable)
#define CR4_SMAP (1u << 21)			// SMAP (Supervisor Mode Access Prevention Enable)	
#define CR4_PKE (1u << 22)			// Protection Key Enable	

#define EFER_SCE 1					// SCE (System Call Extensions)
#define EFER_LME (1 << 8)			// LME (Long Mode Enable)
#define EFER_LMA (1 << 10)			// LMA (Long Mode Active)
#define EFER_NXE (1 << 11)			// NXE (No-Execute Enable)
#define EFER_SVME (1 << 12)			// SVME (Secure Virtual Machine Enable)
#define EFER_LMSLE (1 << 13)		// LMSLE (Long Mode Segment Limit Enable)
#define EFER_FFXSR (1 << 14)		// FFXSR (Fast FXSAVE/FXRSTOR)
#define EFER_TCE (1 << 15)			// TCE (Translation Cache Extension)


// 64-bit page * entry bits 
#define PDE64_PRESENT 1
#define PDE64_RW (1 << 1)
#define PDE64_USER (1 << 2)
#define PDE64_ACCESSED (1 << 5)
#define PDE64_DIRTY (1 << 6)
#define PDE64_PS (1 << 7)
#define PDE64_G (1 << 8)


