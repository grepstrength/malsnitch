#this script can run in either Binja's script console or from the CLI

import json
import sys
from binaryninja import BinaryViewType #needed for Binja's AIP entry point for opening a binary 

def export_strings(bv):
    results = {
        "filename": bv.file.filename, #gives the path
        "arch": bv.arch.name, #gives the system architecture (e.g. x86_64, ARM, etc)
        "platform": str(bv.platform), #gives the OS
        "strings": []
    }

    for string_ref in bv.get_strings(): #returns every string Binja identifies in the binary
        entry = {
            "value": string_ref.value,
            "address": hex(string_ref.start),
            "length": string_ref.length,
            "section": get_section_name(bv.string_ref.start),
            "xrefs": []
        }
        for xref in bv.get_code_refs(string_ref.start): #asks Binja what code locations reference X address?
            func = bv.get_functions_containing(xref.address) #given a code address, returns the functions it belongs to
            if func:
                entry["xrefs"].append({
                    "address": hex(xref.address),
                    "function": func[0].name,
                    "function_address": hex(func[0].start)
                })

        if entry["xrefs"] or len(entry["value"]) >= 8:
            results["strings"].append(entry)

    return results

def get_section_name(bv, address):
    for section_name, section in bv.sections.items(): #loop to find which section contains the address
        if section.start <= address < section.end:
            return section_name
    return "unknown"

def save_export(results, output_path):
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Exported{len(results['strings'])} strings to {output_path}")

#for running entirely from the command line
def run_headless(binary_path, output_path):
    bv = BinaryViewType.get_view_of_file(binary_path)
    if bv is None:
        print(f"Failed to open{binary_path}")
        sys.exit(1)
    results = export_strings(bv)
    save_export(results, output_path)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bn_export.py <binary_path> <output.json>")
        sys.exit(1)
    run_headless(sys.argv[1], sys.argv[2])