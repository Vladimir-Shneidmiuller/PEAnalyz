import pefile


def print_import_table(pe):
    print("\nImport Table:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  DLL Name: {entry.dll.decode('utf-8')}")
        for func in entry.imports:
            print(f"    Function Name: {func.name.decode('utf-8') if func.name else ''}")


def print_dos_header(pe):
    print("DOS Header:")
    print(f"  Magic: {hex(pe.DOS_HEADER.e_magic)}")
    print(f"  Bytes on Last Page of File: {pe.DOS_HEADER.e_cblp}")



def print_file_header(pe):
    print("\nFile Header:")
    print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")



def print_optional_header(pe):
    print("\nOptional Header:")
    print(f"  Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
    print(f"  Address of Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")



def print_section_headers(pe):
    print("\nSection Headers:")
    for section in pe.sections:
        print(f"  Name: {section.Name.decode('utf-8')}")
        print(f"    Virtual Address: {hex(section.VirtualAddress)}")
        print(f"    Size of Raw Data: {section.SizeOfRawData}")



if __name__ == "__main__":
    filename = input("Введите путь к исполняемому файлу: ")

    try:
        pe = pefile.PE(filename)
        print_dos_header(pe)
        print_file_header(pe)
        print_optional_header(pe)
        print_section_headers(pe)
        print_import_table(pe)
    except Exception as e:
        print(f"Ошибка: {str(e)}")


