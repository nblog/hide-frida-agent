# hide-frida-agent
Hide Module "frida-agent.dll"
## processing method
1. unlink. (PEB.Ldr.InLoadOrderLinks 、PEB.Ldr.InMemoryOrderLinks、PEB.Ldr.InitializationOrderLinks)
2. erase pe headers.
3. shield to query the usage area of the module. (ntdll.NtQueryVirtualMemory)
