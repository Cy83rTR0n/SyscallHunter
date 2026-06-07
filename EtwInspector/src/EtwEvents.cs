using EtwInspector.Provider.Enumeration;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace EtwInspector.Events
{
    internal static class EtwEventBuilder
    {
        internal static PSObject Build(TraceEvent data)
        {
            var obj = new PSObject();
            obj.Properties.Add(new PSNoteProperty("TimeStamp",    data.TimeStamp));
            obj.Properties.Add(new PSNoteProperty("ProviderName", data.ProviderName));
            obj.Properties.Add(new PSNoteProperty("ProviderGuid", data.ProviderGuid.ToString("B")));
            obj.Properties.Add(new PSNoteProperty("EventName",    data.EventName));
            obj.Properties.Add(new PSNoteProperty("Id",           (int)data.ID));
            obj.Properties.Add(new PSNoteProperty("Version",      (int)data.Version));
            obj.Properties.Add(new PSNoteProperty("Level",        data.Level.ToString()));
            obj.Properties.Add(new PSNoteProperty("Keywords",     $"0x{(ulong)data.Keywords:X}"));
            obj.Properties.Add(new PSNoteProperty("ProcessId",    data.ProcessID));
            obj.Properties.Add(new PSNoteProperty("ThreadId",     data.ThreadID));
            obj.Properties.Add(new PSNoteProperty("ProcessName",  data.ProcessName));
            obj.Properties.Add(new PSNoteProperty("ActivityId",   data.ActivityID));

            var payload = new System.Collections.Hashtable();
            string[] names = data.PayloadNames;
            for (int i = 0; i < names.Length; i++)
            {
                try   { payload[names[i]] = data.PayloadValue(i); }
                catch { payload[names[i]] = "<error reading value>"; }
            }
            obj.Properties.Add(new PSNoteProperty("Payload", payload));

            return obj;
        }
    }

    /// <summary>
    /// <para type="synopsis">Import-EtwFile reads events from an ETL trace file and outputs them as objects</para>
    /// <para type="description">Parses an ETL file produced by Start-EtwCapture and streams each event as a PSObject containing the provider, event name, timestamp, process/thread IDs, and a Payload hashtable of all event fields. Supports optional filtering by provider GUID, event name, and max event count.</para>
    /// </summary>
    /// <example>
    /// <para>PS C:\> Import-EtwFile C:\research\syscall_trace.etl</para>
    /// </example>
    /// <example>
    /// <para>PS C:\> Import-EtwFile C:\research\trace.etl -ProviderGuid "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" | Where-Object { $_.ProcessName -ne "System" }</para>
    /// </example>
    /// <example>
    /// <para>PS C:\> $mstiEvents = Import-EtwFile C:\research\trace.etl -ProviderGuid "f4e1897c-bb5d-5668-f1d8-040f4d8dd344"</para>
    /// <para>PS C:\> $stackEvents = Import-EtwFile C:\research\trace.etl -ProviderGuid "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"</para>
    /// </example>
    [Cmdlet(VerbsData.Import, "EtwFile")]
    [OutputType(typeof(PSObject))]
    public class ImportEtwFileCommand : PSCmdlet
    {
        /// <summary><para type="description">Path to the ETL file to parse.</para></summary>
        [Parameter(Position = 0, Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        /// <summary><para type="description">Filter output to events from this provider GUID only.</para></summary>
        [Parameter]
        public string ProviderGuid { get; set; }

        /// <summary><para type="description">Filter output to events with this exact event name (case-insensitive).</para></summary>
        [Parameter]
        public string EventName { get; set; }

        /// <summary><para type="description">Stop after emitting this many events. 0 (default) means no limit.</para></summary>
        [Parameter]
        public int MaxEvents { get; set; } = 0;

        protected override void ProcessRecord()
        {
            string resolvedPath;
            try
            {
                resolvedPath = GetUnresolvedProviderPathFromPSPath(Path);
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "InvalidPath", ErrorCategory.InvalidArgument, Path));
                return;
            }

            if (!File.Exists(resolvedPath))
            {
                WriteError(new ErrorRecord(
                    new FileNotFoundException($"ETL file not found: {resolvedPath}"),
                    "FileNotFound", ErrorCategory.ObjectNotFound, resolvedPath));
                return;
            }

            Guid? filterGuid = null;
            if (!string.IsNullOrEmpty(ProviderGuid))
            {
                try { filterGuid = new Guid(ProviderGuid.Trim('{', '}')); }
                catch { WriteWarning($"Could not parse '{ProviderGuid}' as a GUID — provider filter skipped."); }
            }

            int count = 0;
            bool limitReached = false;
            bool stopping = false;

            Action<TraceEvent> handler = data =>
            {
                if (limitReached || stopping) return;
                if (MaxEvents > 0 && count >= MaxEvents) { limitReached = true; return; }
                if (filterGuid.HasValue && data.ProviderGuid != filterGuid.Value) return;
                if (!string.IsNullOrEmpty(EventName) &&
                    !data.EventName.Equals(EventName, StringComparison.OrdinalIgnoreCase)) return;

                WriteObject(EtwEventBuilder.Build(data));
                count++;
            };

            try
            {
                using (var source = new ETWTraceEventSource(resolvedPath))
                {
                    source.Dynamic.All       += data => handler(data);
                    source.Kernel.All        += data => handler(data);
                    source.UnhandledEvents   += data => handler(data);
                    source.Process();
                }
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "ImportEtwFileError", ErrorCategory.ReadError, resolvedPath));
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Get-EtwKeywordMask converts ETW keyword names to a ulong bitmask for use with Start-EtwCapture or Receive-EtwCapture</para>
    /// <para type="description">Looks up the numeric value of each named keyword for the specified manifest provider and returns the OR-combined ulong mask. Use -ListKeywords to enumerate all available keywords with their hex values. The returned mask can be passed directly to -Keywords on Start-EtwCapture or Receive-EtwCapture.</para>
    /// </summary>
    /// <example>
    /// <para>PS C:\> Get-EtwKeywordMask -ProviderGuid "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -ListKeywords</para>
    /// </example>
    /// <example>
    /// <para>PS C:\> $mask = Get-EtwKeywordMask "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -KeywordNames "KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE","KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE"</para>
    /// <para>PS C:\> $session = Start-EtwCapture -ProviderGuids "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -TraceName SyscallTrace -OutputFilePath C:\trace.etl -Keywords $mask</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "EtwKeywordMask", DefaultParameterSetName = "ByName")]
    public class GetEtwKeywordMaskCommand : PSCmdlet
    {
        /// <summary><para type="description">Provider GUID to look up keywords for (Manifest providers only).</para></summary>
        [Parameter(Position = 0, Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string ProviderGuid { get; set; }

        /// <summary><para type="description">One or more keyword names to OR together. Names are matched case-insensitively.</para></summary>
        [Parameter(ParameterSetName = "ByName")]
        public string[] KeywordNames { get; set; }

        /// <summary><para type="description">List all keywords for the provider with their hex values instead of computing a mask.</para></summary>
        [Parameter(ParameterSetName = "List")]
        public SwitchParameter ListKeywords { get; set; }

        protected override void ProcessRecord()
        {
            Guid guid;
            try { guid = new Guid(ProviderGuid.Trim('{', '}')); }
            catch
            {
                WriteError(new ErrorRecord(
                    new ArgumentException($"Invalid GUID: {ProviderGuid}"),
                    "InvalidGuid", ErrorCategory.InvalidArgument, ProviderGuid));
                return;
            }

            // ProviderMetadata requires the friendly provider name, not the GUID.
            // Resolve it from HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{guid}.
            string providerName = null;
            try
            {
                string regPath = $@"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{guid:B}";
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath))
                    providerName = key?.GetValue(null) as string;
            }
            catch { }

            if (string.IsNullOrEmpty(providerName))
            {
                WriteError(new ErrorRecord(
                    new ItemNotFoundException(
                        $"Provider {guid:B} is not registered as a Manifest provider. " +
                        "Only Manifest providers have queryable keyword metadata via this cmdlet."),
                    "ProviderNotFound", ErrorCategory.ObjectNotFound, ProviderGuid));
                return;
            }

            IEnumerable<EventKeyword> keywords;
            try
            {
                var meta = new ProviderMetadata(providerName);
                keywords = meta.Keywords;
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "ProviderMetadataError", ErrorCategory.ReadError, ProviderGuid));
                return;
            }

            if (ListKeywords || KeywordNames == null || KeywordNames.Length == 0)
            {
                foreach (var kw in keywords)
                {
                    var obj = new PSObject();
                    obj.Properties.Add(new PSNoteProperty("Name",        kw.Name));
                    obj.Properties.Add(new PSNoteProperty("Value",       (ulong)kw.Value));
                    obj.Properties.Add(new PSNoteProperty("Hex",         $"0x{(ulong)kw.Value:X16}"));
                    obj.Properties.Add(new PSNoteProperty("Description", kw.DisplayName));
                    WriteObject(obj);
                }
                return;
            }

            ulong mask = 0;
            foreach (string name in KeywordNames)
            {
                var kw = keywords.FirstOrDefault(k =>
                    k.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (kw != null)
                    mask |= (ulong)kw.Value;
                else
                    WriteWarning($"Keyword '{name}' not found in provider {guid:B}.");
            }

            WriteObject(mask);
        }
    }

    /// <summary>
    /// <para type="synopsis">Receive-EtwCapture starts a real-time ETW session and streams events to the pipeline</para>
    /// <para type="description">Creates a real-time ETW trace session (no ETL file), enables the specified providers, and streams each event as a PSObject until stopped with Ctrl+C or until the optional -Duration elapses. Useful for live monitoring during malware sample execution without producing a file on disk.</para>
    /// </summary>
    /// <example>
    /// <para>PS C:\> Receive-EtwCapture -ProviderGuids "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -TraceName SyscallRT | Where-Object { $_.EventName -like "*AllocVm*" }</para>
    /// </example>
    /// <example>
    /// <para>PS C:\> $mask = Get-EtwKeywordMask "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -KeywordNames "KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE","KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE"</para>
    /// <para>PS C:\> Receive-EtwCapture -ProviderGuids "f4e1897c-bb5d-5668-f1d8-040f4d8dd344" -TraceName SyscallRT -Keywords $mask -Duration 60</para>
    /// </example>
    [Cmdlet(VerbsCommunications.Receive, "EtwCapture")]
    [OutputType(typeof(PSObject))]
    public class ReceiveEtwCaptureCommand : PSCmdlet
    {
        /// <summary><para type="description">One or more provider GUIDs to enable on the real-time session.</para></summary>
        [Parameter(Position = 0, Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string[] ProviderGuids { get; set; }

        /// <summary><para type="description">Name for the trace session. Must not already be in use.</para></summary>
        [Parameter(Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string TraceName { get; set; }

        /// <summary><para type="description">ETW keyword bitmask to filter which events are enabled (default: all keywords).</para></summary>
        [Parameter]
        public ulong Keywords { get; set; } = ulong.MaxValue;

        /// <summary><para type="description">How many seconds to capture before automatically stopping. 0 (default) runs until Ctrl+C.</para></summary>
        [Parameter]
        public int Duration { get; set; } = 0;

        private readonly ConcurrentQueue<PSObject> _queue    = new ConcurrentQueue<PSObject>();
        private readonly ManualResetEventSlim       _stopSignal = new ManualResetEventSlim(false);
        private ETWTraceEventSource  _source;
        private TraceEventSession    _session;
        private Thread               _processingThread;
        private Exception            _processingException;

        protected override void ProcessRecord()
        {
            try
            {
                _session = new TraceEventSession(TraceName);

                foreach (string providerStr in ProviderGuids)
                {
                    try
                    {
                        string formatted = providerStr.StartsWith("{") && providerStr.EndsWith("}")
                            ? providerStr
                            : "{" + providerStr.Trim('{', '}') + "}";
                        _session.EnableProvider(new Guid(formatted), TraceEventLevel.Verbose, Keywords);
                    }
                    catch (FormatException)
                    {
                        WriteWarning($"Could not parse '{providerStr}' as a GUID — skipping.");
                    }
                    catch (Exception ex)
                    {
                        WriteWarning($"Failed to enable provider '{providerStr}': {ex.Message}");
                    }
                }

                _source = new ETWTraceEventSource(TraceName, TraceEventSourceType.Session);
                _source.Dynamic.All     += data => _queue.Enqueue(EtwEventBuilder.Build(data));
                _source.Kernel.All      += data => _queue.Enqueue(EtwEventBuilder.Build(data));
                _source.UnhandledEvents += data => _queue.Enqueue(EtwEventBuilder.Build(data));

                _processingThread = new Thread(() =>
                {
                    try   { _source.Process(); }
                    catch (Exception ex) { _processingException = ex; }
                    finally { _stopSignal.Set(); } // unblock main thread if processing dies
                }) { IsBackground = true };

                _processingThread.Start();

                var deadline = Duration > 0
                    ? DateTime.UtcNow.AddSeconds(Duration)
                    : DateTime.MaxValue;

                while (!_stopSignal.Wait(50) && DateTime.UtcNow < deadline)
                {
                    while (_queue.TryDequeue(out var item))
                        WriteObject(item);
                }

                _source.StopProcessing();
                _processingThread.Join(3000);

                // Flush any events enqueued between the last poll and stop
                while (_queue.TryDequeue(out var remaining))
                    WriteObject(remaining);

                if (_processingException != null)
                    WriteError(new ErrorRecord(
                        _processingException,
                        "ReceiveEtwProcessingError",
                        ErrorCategory.ReadError,
                        TraceName));
            }
            catch (UnauthorizedAccessException)
            {
                WriteError(new ErrorRecord(
                    new UnauthorizedAccessException(
                        "Access denied creating trace session. Some providers (e.g., Microsoft-Windows-Threat-Intelligence) " +
                        "require elevated privileges or a PPL consumer. Run as Administrator or use NT Kernel Logger instead."),
                    "AccessDenied", ErrorCategory.PermissionDenied, TraceName));
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "ReceiveEtwCaptureError", ErrorCategory.OperationStopped, TraceName));
            }
            finally
            {
                _source?.Dispose();
                _session?.Dispose();
            }
        }

        protected override void StopProcessing()
        {
            _stopSignal.Set();
            _source?.StopProcessing();
        }
    }
}
