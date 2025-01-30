import os

# Output results file
results_file = "cracked_results.txt"

# Mapping files for usernames
mapping_files = {
    "NTLM": "ntlm_mapping.txt",
    "LM": "lm_mapping.txt",
    "DCC2": "dcc_mapping.txt",
    "AES128": "aes128_mapping.txt",
    "AES256": "aes256_mapping.txt",
    "DES-CBC-MD5": "des_mapping.txt",
}


def parse_potfile(potfile):
    """
    Parses the Hashcat potfile and returns a dictionary of {hash: password}.
    """
    cracked_hashes = {}
    try:
        with open(potfile, "r") as f:
            for line in f:
                # Potfile format: <hash>:<password>
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    hash, password = parts
                    cracked_hashes[hash] = password
        print(f"\n📂 Loaded {len(cracked_hashes)} cracked hashes from potfile: {potfile}")
    except FileNotFoundError:
        print(f"❌ Error: Potfile '{potfile}' not found. Please check the path.")
    return cracked_hashes


def match_hashes(mapping_files, cracked_hashes):
    """
    Matches cracked hashes with usernames and writes the results to both terminal and a file.
    """
    results = []
    found_anything = False  # Tracks whether any matches were found

    print("\n🔍 Matching cracked hashes with usernames...\n")

    for hash_type, mapping_file in mapping_files.items():
        if not os.path.exists(mapping_file):
            print(f"⚠️ No {hash_type} mapping file found. Skipping {hash_type}.")
            continue

        found_hashes = False
        with open(mapping_file, "r") as f:
            for line in f:
                username, hash = line.strip().split(":", 1)
                if hash in cracked_hashes:
                    found_hashes = True
                    found_anything = True
                    results.append(f"{username}:{cracked_hashes[hash]} ({hash_type})")

        if found_hashes:
            print(f"✅ Cracked {hash_type} hashes found and matched!")
        else:
            print(f"❌ No cracked {hash_type} hashes found in potfile.")

    # Write results to a file, even if no matches were found
    with open(results_file, "w") as f:
        if results:
            f.write("\n".join(results))
            print(f"\n📜 Matched cracked hashes written to: {results_file}")
        else:
            f.write("🚫 No cracked hashes matched with usernames.\n")
            print("\n🚫 No cracked hashes matched with usernames. File written for reference.")

    return results


def main():
    print("\n=======================================================")
    print("🔎 🔑  Hash Matching Script  🔑 🔎")
    print("This script matches cracked hashes from the Hashcat potfile")
    print("with their corresponding usernames from parsed mappings.")
    print("=======================================================\n")

    potfile = input("📄 Enter the path to the Hashcat potfile: ").strip()

    if not os.path.exists(potfile):
        print(f"❌ Error: File '{potfile}' not found. Please check the path and try again.")
        return

    cracked_hashes = parse_potfile(potfile)
    results = match_hashes(mapping_files, cracked_hashes)

    if results:
        print("\n🎯 Matched Cracked Hashes:")
        for result in results:
            print(f"   {result}")
    else:
        print("\n🚫 No matches found for any hashes.")


if __name__ == "__main__":
    main()
