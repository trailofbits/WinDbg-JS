"use strict";

function initializeScript()
{
    return [new host.functionAlias(AllRegisteredLoggersWithConsumers, "EtwLoggersAndConsumers"),
            new host.functionAlias(EtwConsumersForProcess, "EtwConsumersForProcess"),
            new host.functionAlias(EtwConsumersForAllProcesses, "EtwConsumersForAllProcesses"),
            new host.functionAlias(EtwRegisteredGuids, "EtwRegisteredGuids"),
            new host.functionAlias(EtwProvidersForProcess, "EtwProvidersForProcess"),
            new host.functionAlias(EtwProvidersForAllProcesses, "EtwProvidersForAllProcesses"),
            new host.apiVersionSupport(1, 7)];
}

function invokeScript()
{
    //
    // Insert your script content here.  This method will be called whenever the script is
    // invoked from a client.
    //
    // See the following for more details:
    //
    //     https://aka.ms/JsDbgExt
    //
}

function GetGuidsForLoggerId(loggerId, guidType)
{
    let dbgOutput = host.diagnostics.debugLog;

    let guidArray = new Array();

    let hostSiloGlobals = host.getModuleSymbolAddress("nt", "PspHostSiloGlobals");
    let typedhostSiloGlobals = host.createTypedObject(hostSiloGlobals, "nt", "_ESERVERSILO_GLOBALS");
    let guidHashTable = typedhostSiloGlobals.EtwSiloState.EtwpGuidHashTable;
    // As a performance optimization, since Windows 8 the reigstered GUIDs are
    // organized in 64 hash buckets instead of one big list.
    // Each hash bucket contains a list of all GUIDs with a matching hash.
    for (let bucket of guidHashTable)
    {
        // There are three GUID types in each bucket, deinfed in ETW_GUID_TYPE enum:
        // - EtwTraceGuidType = 0
        // - EtwNotificationGuidType = 1
        // - EtwGroupGuidType = 2
        // There is a linked list for each type in every bucket.
        // Collect GUIDs of the type requested by the caller.
        // Most common type is EtwTraceGuidType.
        let guidEntries = host.namespace.Debugger.Utility.Collections.FromListEntry(bucket.ListHead[guidType], "nt!_ETW_GUID_ENTRY", "GuidList");
        if (guidEntries.Count() != 0)
        {
            for (let guid of guidEntries)
            {
                if (loggerId === -1)
                {
                    guidArray.push(guid);
                }
                else
                {
                    for (let enableInfo of guid.EnableInfo)
                    {
                        if (enableInfo.LoggerId === loggerId)
                        {
                            guidArray.push(guid);
                            break;
                        }
                    }
                }
            }
        }
    }
    return guidArray;
}

function EtwRegisteredGuids()
{
    let dbgOutput = host.diagnostics.debugLog;
    let guidsArrays = new Array();
    guidsArrays[0] = GetGuidsForLoggerId(-1, 0);
    guidsArrays[1] = GetGuidsForLoggerId(-1, 1);
    guidsArrays[2] = GetGuidsForLoggerId(-1, 2);

    let guidTypes;
    guidTypes = [
        "EtwTraceGuidType",
        "EtwNotificationGuidType",
        "EtwGroupGuidType"
    ];

    for (let i in guidsArrays)
    {
        if (guidsArrays[i].length != 0)
        {
            dbgOutput("Printing GUIDs for type ", guidTypes[i], ":\n");
            for (let guid of guidsArrays[i])
            {
                if (guid.LastEnable.Enabled) // only print enabled GUIDs
                {
                    dbgOutput("\tETW Guid Entry: ", guid.address, "\n");
                    dbgOutput("\tGuid: ", guid.Guid, "\n");
                    dbgOutput("\tSecurity Descriptor: ", guid.SecurityDescriptor.address, "\n");
                    dbgOutput("\tLogger ID: ", guid.LastEnable.LoggerId, "\n");

                    let regEntryLinkField = "RegList";
                    if (i == 2)
                    {
                        // group GUIDs registration entries are linked through the GroupRegList field
                        regEntryLinkField = "GroupRegList";
                    }
                    let regEntries = host.namespace.Debugger.Utility.Collections.FromListEntry(guid.RegListHead, "nt!_ETW_REG_ENTRY", regEntryLinkField);
                    if (regEntries.Count() != 0)
                    {
                        dbgOutput("\tRegistration entries: \n");
                        for (let regEntry of regEntries)
                        {
                            dbgOutput("\t\tETW_REG_ENTRY: ", regEntry.address, "\n");
                            if ((regEntry.DbgUserRegistration != 0) && (host.parseInt64(regEntry.Process.address, 16).compareTo(host.parseInt64(0)) != 0))
                            {
                                try {
                                    dbgOutput("\t\t\tProcess: ", regEntry.Process.SeAuditProcessCreationInfo.ImageFileName.Name, " ID: ", host.parseInt64(regEntry.Process.UniqueProcessId.address, 16).toString(10), "\n");
                                } catch (e) {

                                }
                            }
                            if (host.parseInt64(regEntry.Callback.address, 16).compareTo(host.parseInt64(0)) != 0)
                            {
                                if (regEntry.DbgKernelRegistration != 0)
                                {
                                    let callback_sym = host.namespace.Debugger.Utility.Control.ExecuteCommand(".printf \"%y\"," + host.parseInt64(regEntry.Callback.address, 16).toString());
                                    dbgOutput("\t\t\tKernel registration. Callback: ", callback_sym.First(), "\n");
                                }
                                else
                                {
                                    dbgOutput("\t\t\t\tCallback: ", regEntry.Callback.address, "\n");
                                }
                            }
                        }
                    }
                     dbgOutput("\n");
                }
            }
        }
    }
}

function AllRegisteredLoggersWithConsumers()
{
    let dbgOutput = host.diagnostics.debugLog;
    let hostSiloGlobals = host.getModuleSymbolAddress("nt", "PspHostSiloGlobals");
    let typedhostSiloGlobals = host.createTypedObject(hostSiloGlobals, "nt", "_ESERVERSILO_GLOBALS");

    let maxLoggers = typedhostSiloGlobals.EtwSiloState.MaxLoggers;
    for (let i = 0; i < maxLoggers; i++)
    {
        let logger = typedhostSiloGlobals.EtwSiloState.EtwpLoggerContext[i];
        if (host.parseInt64(logger.address, 16).compareTo(host.parseInt64("0x1")) != 0)
        {
            dbgOutput("WMI Logger Context: ", logger.address, "\n");
            dbgOutput("\tName: ", logger.LoggerName, "\n");
            dbgOutput("\tLoggerId: ", logger.LoggerId, "\n");
            dbgOutput("\tInstance Guid: ", logger.InstanceGuid, "\n");
            dbgOutput("\tRealtime Log File Name: ", logger.RealtimeLogfileName, "\n");
            if ((logger.LoggerMode & 0x2000000) == 0x2000000)
            {
                dbgOutput("\t** This is a system trace logger **\n");
            }

            let consumers = host.namespace.Debugger.Utility.Collections.FromListEntry(logger.Consumers, "nt!_ETW_REALTIME_CONSUMER", "Links");
            if (consumers.Count() != 0)
            {
                dbgOutput("\tConsumers:\n");
                for (let consumer of consumers)
                {
                    dbgOutput("\t\tName: ", consumer.ProcessObject.SeAuditProcessCreationInfo.ImageFileName.Name, "\n");
                    dbgOutput("\t\tId: ", host.parseInt64(consumer.ProcessObject.UniqueProcessId.address, 16).toString(10), "\n");
                }
            }
            // we only care about trace guids in this case
            let guidArray = GetGuidsForLoggerId(logger.LoggerId, 0);
            if (guidArray.length != 0)
            {
                dbgOutput("\tGuids:\n");
                for (let guid of guidArray)
                {
                    for (let enableInfo of guid.EnableInfo)
                    {
                        if ((enableInfo.LoggerId === logger.LoggerId) && (enableInfo.IsEnabled))
                        {
                            dbgOutput("\t\t", guid.Guid, "\n");
                        }
                    }
                }
            }
            dbgOutput("\n");
        }
    }
}

function EtwConsumersForProcess(process)
{
    let dbgOutput = host.diagnostics.debugLog;
    let hostSiloGlobals = host.getModuleSymbolAddress("nt", "PspHostSiloGlobals");
    let typedhostSiloGlobals = host.createTypedObject(hostSiloGlobals, "nt", "_ESERVERSILO_GLOBALS");

    dbgOutput("ETW consumers for process ", process.Name, " with ID ", process.Id, ":\n");
    let handles = process.Io.Handles;

    try 
    {
        for (let handle of handles)
        {
            try
            {
                let objType = handle.Object.ObjectType;
                if (objType === "EtwConsumer")
                {
                    let consumer = host.createTypedObject(handle.Object.Body.address, "nt", "_ETW_REALTIME_CONSUMER");
                    let loggerId = consumer.LoggerId;
                    let logger = typedhostSiloGlobals.EtwSiloState.EtwpLoggerContext[loggerId];

                    dbgOutput("\tETW Realtime Consumer: ", consumer.address, "\n");
                    dbgOutput("\t\tWMI Logger Context: ", logger.address, "\n");
                    dbgOutput("\t\tName: ", logger.LoggerName, "\n");
                    dbgOutput("\t\tLoggerId: ", loggerId, "\n");
                    dbgOutput("\t\tInstance Guid: ", logger.InstanceGuid, "\n");
                    dbgOutput("\t\tRealtime Log File Name: ", logger.RealtimeLogfileName, "\n");
                    let guidArray = GetGuidsForLoggerId(loggerId, 0);
                    if (guidArray.length != 0)
                    {
                        dbgOutput("\t\tProvider Guids:\n");
                        for (let guid of guidArray)
                        {
                            if (guid.LastEnable.Enabled) // only show enabled GUIDs
                            {
                                dbgOutput("\t\t\t", guid.Guid, "\n");
                            }
                        }
                    }
                    else
                    {
                        dbgOutput("\t\t** No provider GUIDs are registered for this logger **\n");
                    }
                    dbgOutput("\n");
                }
            } catch (e) {
                dbgOutput("\tException parsing handle ", handle.Handle, "in process ", process.Name, "!\n");
            }
        }
    } catch (e) {

    }
}

function EtwProvidersForProcess(process)
{
    let dbgOutput = host.diagnostics.debugLog;
    dbgOutput("ETW providers for process ", process.Name, " with ID ", process.Id, ":\n");
    let handles = process.Io.Handles;

    try 
    {
        for (let handle of handles)
        {
            try
            {
                let objType = handle.Object.ObjectType;
                if (objType === "EtwRegistration")
                {
                    let regEntry = host.createTypedObject(handle.Object.Body.address, "nt", "_ETW_REG_ENTRY");
                    dbgOutput("\t", regEntry.GuidEntry.Guid, "\n");
                }
            } catch (e) {
                dbgOutput("\tException parsing handle ", handle.Handle, "in process ", process.Name, "!\n");
            }
        }
    } catch (e) {

    }
}

function EtwConsumersForAllProcesses()
{
    let dbgOutput = host.diagnostics.debugLog;
    let processes = host.currentSession.Processes;
    for (let process of processes)
    {
        EtwConsumersForProcess(process);
        dbgOutput("\n");
    }
}

function EtwProvidersForAllProcesses()
{
    let dbgOutput = host.diagnostics.debugLog;
    let processes = host.currentSession.Processes;
    for (let process of processes)
    {
        EtwProvidersForProcess(process);
        dbgOutput("\n");
    }
}
