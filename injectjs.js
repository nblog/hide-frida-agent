
const ptrlength = Process.pointerSize;

const RtlGetCurrentPeb = new NativeFunction(
    Module.getExportByName("ntdll.dll", "RtlGetCurrentPeb"),
    "pointer",
    []
);

// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid
const GetProcessId = new NativeFunction(
    Module.getExportByName("kernel32.dll", "GetProcessId"),
    "uint32",
    ["pointer"]
);

// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
const GetCurrentProcess = new NativeFunction(
    Module.getExportByName("kernel32.dll", "GetCurrentProcess"),
    "pointer",
    []
);

// https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlzeromemory
const RtlZeroMemory = new NativeFunction(
    Module.getExportByName("ntdll.dll", "RtlZeroMemory"),
    "void",
    ["pointer", "size_t"]
);

// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
const VirtualProtect = new NativeFunction(
    Module.getExportByName("kernel32.dll", "VirtualProtect"),
    "int",
    ["pointer", "size_t", "uint32", "pointer"]
);


// https://github.com/frida/frida-core/blob/main/lib/agent/frida-agent.def
const frida_agent = (function() {
    let hModule = Module.getBaseAddress("frida-agent.dll");
    // https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-moduleinfo
    const ModuleInfoSize = 3 * ptrlength;
    let ModuleInfoPtr = Memory.alloc(ModuleInfoSize);
    // https://learn.microsoft.com/windows/win32/api/psapi/nf-psapi-getmoduleinformation
    new NativeFunction(
        Module.getExportByName("psapi.dll", "GetModuleInformation"),
        "bool",
        ["pointer", "pointer", "pointer", "uint32"]
    )(GetCurrentProcess(), hModule, ModuleInfoPtr, ModuleInfoSize);
    return {
        base: ModuleInfoPtr.add(0 * ptrlength).readPointer(),
        size: ModuleInfoPtr.add(1 * ptrlength).readU32(),
        entry: ModuleInfoPtr.add(2 * ptrlength).readPointer(),
    }
})();


// https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-removeentrylist
function RemoveEntryList(
    Entry
) {
    const Flink = Entry.add(0 * ptrlength).readPointer();
    const Blink = Entry.add(1 * ptrlength).readPointer();

    Blink.add(0 * ptrlength).writePointer(Flink)
    Flink.add(1 * ptrlength).writePointer(Blink)

    return Flink.equals(Blink);
}

function EnumEntryList(
    ldr,
    InOrderLinks
) {
    const OrderModuleTail = ldr.add(InOrderLinks * (2 * ptrlength)).add(ptrlength).readPointer();

    var OrderModuleHead = OrderModuleTail;

    do {
        const pLdrDataEntry = OrderModuleHead.sub(InOrderLinks * (2 * ptrlength));

        if (pLdrDataEntry.isNull() 
        || pLdrDataEntry.add(6 * ptrlength).readPointer().isNull())
            break;
        
        const DllBase = pLdrDataEntry.add(6 * ptrlength).readPointer();
        const EntryPoint = pLdrDataEntry.add(7 * ptrlength).readPointer();
        const SizeOfImage = pLdrDataEntry.add(8 * ptrlength).readU32();
        const FullDllName = pLdrDataEntry.add(9 * ptrlength);
        const BaseDllName = pLdrDataEntry.add(9 * ptrlength + (2 * ptrlength));

        /*
        console.log(`\n` + 
            `base: ${DllBase}\n` + 
            `size: ${SizeOfImage}\n` + 
            `full: ${FullDllName.add(ptrlength).readPointer().readUtf16String()}\n` + 
            `name: ${BaseDllName.add(ptrlength).readPointer().readUtf16String()}\n`);
        */

        if (frida_agent.base.equals(DllBase)) {

            FullDllName.add(0).writeU16(0);
            FullDllName.add(2).writeU16(0);
            FullDllName.add(ptrlength).writePointer(ptr(0));

            BaseDllName.add(0).writeU16(0);
            BaseDllName.add(2).writeU16(0);
            BaseDllName.add(ptrlength).writePointer(ptr(0));

            RemoveEntryList(OrderModuleHead)
        }

        OrderModuleHead = OrderModuleHead.add(ptrlength).readPointer();
        
    } while(!OrderModuleHead.equals(OrderModuleTail));
}

function GetPebPtr() {
    return RtlGetCurrentPeb();
}

function GetPebLdrDataPtr(PebPtr) {
    return PebPtr.add(3 * ptrlength).readPointer().add(4 + 4 + ptrlength);
}

function HideInLoadOrderLinks() {
    const PebPtr = GetPebPtr();
    const ldr = GetPebLdrDataPtr(PebPtr);
    EnumEntryList(ldr, 0);
}

function HideInMemoryOrderLinks() {
    const PebPtr = GetPebPtr();
    const ldr = GetPebLdrDataPtr(PebPtr);
    EnumEntryList(ldr, 1);
}

function HideInInitializationOrderLinks() {
    const PebPtr = GetPebPtr();
    const ldr = GetPebLdrDataPtr(PebPtr);
    EnumEntryList(ldr, 2);
}

function EraseHeaders() {
    const page_size = Process.pageSize;

    const PAGE_READWRITE = 0x04;

    var lpflOldProtect = Memory.alloc(4);
    VirtualProtect(frida_agent.base, page_size, PAGE_READWRITE, lpflOldProtect);
    RtlZeroMemory(frida_agent.base, page_size);
    VirtualProtect(frida_agent.base, page_size, lpflOldProtect.readU32(), lpflOldProtect);
}


function ShieldQuery() {
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
    const NtQueryVirtualMemoryPtr = Module.getExportByName("ntdll.dll", "NtQueryVirtualMemory");

    Interceptor.attach(NtQueryVirtualMemoryPtr, {
        onEnter(args) {
            this.bSkip = false;

            const ProcessHandle = args[0];
            const BaseAddress = args[1];
            const MemoryInformationClass = args[2].toInt32();

            const MemoryInformationLength = args[4];
            this.MemoryInformation = args[3];
            this.ReturnLength = args[5];

            // detect if the current process is the target process
            if (GetCurrentProcess() != ProcessHandle 
            || Process.id != GetProcessId(ProcessHandle)) return;

            // detect if the query is for the frida agent module
            if (BaseAddress >= frida_agent.base 
                && BaseAddress <= frida_agent.base.add(frida_agent.size)) {
                console.log(`detecting ${BaseAddress} in "frida-agent" module.`);
                this.bSkip = true;
            }
        },
        onLeave(retval) {
            if (this.bSkip) {
                const STATUS_ACCESS_DENIED = ptr(0xC0000022);
                retval.replace(STATUS_ACCESS_DENIED);
            }
        }
    });
}

HideInLoadOrderLinks();
HideInMemoryOrderLinks();
HideInInitializationOrderLinks();
ShieldQuery();
EraseHeaders();

console.log(`!!! warn: exception thrown when uninstalling(exit) module !!!`);
