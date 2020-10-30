

const ptrlength = Process.pointerSize;

const frida_agent = "frida-agent.dll"
const moudleInfos = Module.load(frida_agent)


// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlzeromemory
const RtlZeroMemory = new NativeFunction(Module.getExportByName("ntdll.dll", "RtlZeroMemory"), 
    "void", 
    ["pointer", "pointer"]);

// https://docs.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
const VirtualProtect = new NativeFunction(Module.getExportByName("kernel32.dll", "VirtualProtect"), 
    "bool", 
    ["pointer", "pointer", "uint32", "pointer"]);

const RtlGetCurrentPeb = new NativeFunction(Module.getExportByName("ntdll.dll", "RtlGetCurrentPeb"), 
    "pointer", 
    []);

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-removeentrylist
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

        // console.log("\n\nbase: " + DllBase
        //     + "\nsize: " + SizeOfImage
        //     + "\nfull: " + FullDllName.add(ptrlength).readPointer().readUtf16String()
        //     + "\nname: " + BaseDllName.add(ptrlength).readPointer().readUtf16String()
        // );

        if (moudleInfos.base.equals(DllBase)) {

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
    const page = Process.pageSize;

    const PAGE_READWRITE = 0x04;

    var lpflOldProtect = Memory.alloc(4);
    VirtualProtect(moudleInfos.base, ptr(page), PAGE_READWRITE, lpflOldProtect);
    RtlZeroMemory(moudleInfos.base, ptr(page));
    VirtualProtect(moudleInfos.base, ptr(page), lpflOldProtect.readU32(), lpflOldProtect);
}


function ShieldQuery() {
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid
    const GetProcessId = new NativeFunction(Module.getExportByName("kernel32.dll", "GetProcessId"), 
    "uint32", 
    ["pointer"]);

    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    const GetCurrentProcess = new NativeFunction(Module.getExportByName("kernel32.dll", "GetCurrentProcess"), 
    "pointer", 
    []);

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
    const NtQueryVirtualMemoryPtr = Module.getExportByName("ntdll.dll", "NtQueryVirtualMemory");

    Interceptor.attach(NtQueryVirtualMemoryPtr, {
    onEnter(args) {

        this.bSkip = false;

        const ProcessHandle = args[0];
        const BaseAddress = args[1];
        const MemoryInformationClass = args[2].toInt32();
        
        if (GetCurrentProcess() == ProcessHandle 
            || Process.id == GetProcessId(ProcessHandle)) {
            console.log("check self.\n");
            
            if (BaseAddress >= moudleInfos.base 
                && BaseAddress <= moudleInfos.base.add(moudleInfos.size)) {
                console.log("check addr: " + BaseAddress
                    + "in \"" + frida_agent + "\" module.\n");
                this.bSkip = true;
            }
        }

        const MemoryInformationLength = args[4];
        this.MemoryInformation = args[3];
        this.ReturnLength = args[5];
    },
    onLeave(retval) {
        if (this.bSkip) {
            // STATUS_ACCESS_DENIED (0xC0000022)
            retval.replace(ptr("0xC0000022"));
        }
    }
    });
}

HideInLoadOrderLinks();
HideInMemoryOrderLinks();
HideInInitializationOrderLinks();
ShieldQuery();
EraseHeaders();