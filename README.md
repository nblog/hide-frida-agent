# hide-frida-agent
Hide Module "frida-agent.dll"
## the processing method is as follows
1. unlink. (InLoadOrderLinks 、InMemoryOrderLinks、InitializationOrderLinks)
2. erase pe headers.
3. shield to query the usage area of the module.
