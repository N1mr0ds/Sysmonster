import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import pefile
import winreg
import time
import ctypes
import sys
import json
from datetime import datetime

dir_path = "sysmon_versions"

home_dir = Path(f"{dir_path}")
analyze_file = Path(f"{dir_path}\\versions.txt")
schema_dir = home_dir / "schems"
policy_dir = home_dir / "policies"
bytes_file = home_dir / "bytes.txt"
json_file = home_dir / "sysmon_versions.json"

# Global list to collect version data for JSON
versions_data = []


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def get_md5_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest().upper()

def get_product_version(exe_path):
    """Extract product version from PE file."""
    try:
        pe = pefile.PE(exe_path)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            version_info = pe.FileInfo[0]
            for entry in version_info:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for key, value in st.entries.items():
                            if key.decode() == 'ProductVersion':
                                return value.decode()
    except:
        pass
    return None

def create_policy_xml(schema_version, events, sysmon_version_number, output_path):
    """Create empty Sysmon policy XML file from event schema."""
    root = ET.Element("Sysmon", schemaversion=schema_version)
    
    hash_elem = ET.SubElement(root, "HashAlgorithms")
    hash_elem.text = "md5,sha256,IMPHASH"
    
    event_filtering = ET.SubElement(root, "EventFiltering")
    
    event_list = []
    for child in events:
        rulename = child.get('rulename')
        if rulename and (rulename not in event_list):
            event_list.append(rulename)
            
            if sysmon_version_number > 8:
                rule_group = ET.SubElement(event_filtering, "RuleGroup", name="", groupRelation="or")
                ET.SubElement(rule_group, rulename, onmatch="include")
            else:
                ET.SubElement(event_filtering, rulename, onmatch="include")
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)

def save_json_versions():
    """Save collected version data to JSON file."""
    # Custom JSON formatting to keep byteRule arrays on single line
    indent1 = "  "
    indent2 = "    "
    indent3 = "      "
    
    with open(json_file, "w") as f:
        f.write("{\n")
        f.write(f'{indent1}"metadata": {{\n')
        f.write(f'{indent2}"description": "Sysmon version database with binary signatures",\n')
        f.write(f'{indent2}"source": "Sysmonster Silent Mode Version Analysis"\n')
        f.write(f'{indent1}}},\n')
        f.write(f'{indent1}"versions": [\n')
        
        for idx, version in enumerate(versions_data):
            f.write(f'{indent2}{{\n')
            f.write(f'{indent3}"sysmonVersion": "{version["sysmonVersion"]}",\n')
            f.write(f'{indent3}"schemaVersion": "{version["schemaVersion"]}",\n')
            f.write(f'{indent3}"byteRule": {json.dumps(version["byteRule"])}\n')
            f.write(f'{indent2}}}')
            if idx < len(versions_data) - 1:
                f.write(',\n')
            else:
                f.write('\n')
        
        f.write(f'{indent1}]\n')
        f.write('}\n')
    
    print(f"JSON file saved: {json_file} ({len(versions_data)} versions)")

def process_sysmon_file(file_path):
    """Process a single Sysmon executable, extract version, schema, and registry bytes for sysmonster"""
    with open(analyze_file, "a") as f:
        f.write("-------------------------------------------\n")
        
        # Calculate MD5 hash
        file_hash = get_md5_hash(file_path)
        f.write(f"{file_hash}\n")
        
        # Get product version
        sysmon_version = get_product_version(file_path)
        if not sysmon_version:
            return
        
        f.write(f"Sysmon Version: {sysmon_version}\n")
        
        sysmon_major_version = int(sysmon_version.split('.')[0])
        
        # Schema extraction is supported for Sysmon v6 and above
        if sysmon_major_version > 5:
            try:
                # Run sysmon -s to get schema
                result = subprocess.run(
                    [str(file_path), "-s"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Extract XML from output
                output_parts = result.stdout.split("Sysinternals - www.sysinternals.com")
                if len(output_parts) > 1:
                    policy_xml = output_parts[1].strip()
                    
                    xml_path = schema_dir / f"{sysmon_version}.xml"
                    with open(xml_path, "w", encoding="utf-8") as xml_file:
                        xml_file.write(policy_xml)
                    
                    # Parse XML
                    root = ET.fromstring(policy_xml)
                    schema_version = root.get('schemaversion')
                    binary_version = root.get('binaryversion')
                    
                    f.write(f"SchemaVersion: {schema_version} | BinaryVersion: {binary_version}\n")
                    
                    # Get events
                    events = root.find('events')
                    if events is not None:
                        # Create empty policy XML
                        xml_policy_path = policy_dir / f"{sysmon_version}.xml"
                        create_policy_xml(schema_version, events, sysmon_major_version, xml_policy_path)
                        
                        # Install sysmon and capture registry bytes
                        # Install with empty policy
                        subprocess.run(
                            [str(file_path), "-i", str(xml_policy_path)],
                            capture_output=True,
                            text=True,
                            timeout=60
                        )
                        
                        # Save registry bytes to file for sysmonster
                        try:
                            registry_path = r"SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
                            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey:
                                with winreg.OpenKey(hkey, registry_path) as subkey:
                                    rules_value, value_type = winreg.QueryValueEx(subkey, "Rules")
                                    # Convert binary data to hex string representation for PowerShell format
                                    byte_values = [str(byte) for byte in rules_value]
                                    byte_string = f"@({','.join(byte_values)})"
                                    
                                    with open(bytes_file, "a") as bf:
                                        bf.write("-----------------------------\n")
                                        bf.write(f"Sysmon Version: {sysmon_version}\n")
                                        bf.write(f"Schema Version: {schema_version}\n")
                                        bf.write(f"Binary Version: {binary_version}\n")
                                        bf.write(f"{byte_string}\n")
                                    
                                    # Add to JSON data collection
                                    version_entry = {
                                        "sysmonVersion": sysmon_version,
                                        "schemaVersion": schema_version,
                                        "byteRule": list(rules_value)  # Convert to list of integers
                                    }
                                    versions_data.append(version_entry)
                        except FileNotFoundError:
                            print("Registry key not found")
                        except Exception as e:
                            print(f"Error reading registry: {e}")

                        # Uninstall sysmon
                        subprocess.run(
                            [file_path, "-u"],
                            capture_output=True,
                            text=True,
                            timeout=60
                        )
                        
                        # Remove sysmon.exe if it still exists after uninstallation
                        sysmon_path = Path(f"C:\\Windows\\{file_path.name}")
                        try:
                            if sysmon_path.exists():
                                sysmon_path.unlink()
                        except PermissionError:
                            for _ in range(6):
                                time.sleep(0.5)
                                try:
                                    Path(sysmon_path).unlink()
                                    break
                                except PermissionError:
                                    continue
                        
                        except Exception as e:
                            print(f"Error during Sysmon installation/registry read: {e}")
            
            except subprocess.TimeoutExpired:
                print(f"Timeout processing {file_path}")
            except FileNotFoundError as e:
                print(f"Error processing {file_path}: {repr(e)}")

if __name__ == "__main__":
    # Check for admin privileges
    if not is_admin():
        print("Error: This script requires administrator privileges.")
        print("Please run this script as an administrator.")
        sys.exit(1)
    
    schema_dir.mkdir(exist_ok=True)
    policy_dir.mkdir(exist_ok=True)
    
    # Process each Sysmon version
    for sysmon_exe in home_dir.rglob("Sysmon_*.exe"):
        print(f"Processing {sysmon_exe}...")
        process_sysmon_file(sysmon_exe)
    
    # Save all collected data to JSON file
    if versions_data:
        save_json_versions()
    else:
        print("No version data collected.")