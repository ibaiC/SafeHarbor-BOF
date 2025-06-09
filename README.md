# Safe Harbor
Safe Harbor is a Beacon Object File (BOF) tool for Windows that streamlines process reconnaissance for red team operations. It identifies trusted, appropriate target processes to maintain stealth and robust operational security (OPSEC) during post-exploitation activities.

## Features
- Identify RWX process regions
- Identify useful loaded DLLs like wininet.dll and winhttp.dll
- Find .NET processes
- Find processes with signed binaries
- Serves as a hands-on example of building basic BOFs to extend C2 functionality.

## Usage
Compile the project. Once built, load the .cna script into Cobalt Strike and run it on the target system through the `safe_harbor` command.

![image](https://github.com/user-attachments/assets/3722c127-c0e8-4b17-9b40-83b9dd47fcf8)

## Future Improvements
Targeted Enumeration: Allow operators to specify a PID to scan a particular process instead of all processes.
Optimized Handle Usage: Reduce the number of handles requested to further lower telemetry.
Expanded DLL Search: Add more trusted DLLs to the search criteria for a broader process evaluation.

## References
- https://rwxstoned.github.io/2024-12-06-GimmeShelter/
