import re
import os

# Output files
ntlm_file = "ntlm_hashes.txt"
lm_file = "lm_hashes.txt"
dcc_file = "dcc_hashes.txt"
aes128_file = "aes128_hashes.txt"
aes256_file = "aes256_hashes.txt"
des_file = "des_hashes.txt"

# Mapping files for usernames
ntlm_mapping_file = "ntlm_mapping.txt"
lm_mapping_file = "lm_mapping.txt"
dcc_mapping_file = "dcc_mapping.txt"
aes128_mapping_file = "aes128_mapping.txt"
aes256_mapping_file = "aes256_mapping.txt"
des_mapping_file = "des_mapping.txt"


def parse_secretsdump(input_file):
    """
    Parses the secretsdump.py output and extracts all hash types.
    Saves separate hash files and username-to-hash mapping files.
    """
    ntlm_hashes = {}
    lm_hashes = {}
    dcc_hashes = {}
    aes128_hashes = {}
    aes256_hashes = {}
    des_hashes = {}

    try:
        with open(input_file, "r") as f:
            for line in f:
                # Match NTLM and LM hashes (standard format from secretsdump)
                match_ntlm = re.match(r"^([^:]+):[^:]+:([^:]+):([^:]+):.*$", line.strip())
                if match_ntlm:
                    username, lm_hash, ntlm_hash = match_ntlm.groups()
                    # Only save valid (non-placeholder) LM and NTLM hashes
                    if lm_hash != "aad3b435b51404eeaad3b435b51404ee":
                        lm_hashes[username] = lm_hash
                    if ntlm_hash != "aad3b435b51404eeaad3b435b51404ee":
                        ntlm_hashes[username] = ntlm_hash

                # Match DCC2 hashes (Domain Cached Credentials)
                match_dcc = re.match(r"^([^:]+):[^:]+:\$DCC2\$10240#([^:]+):([^:]+)", line.strip())
                if match_dcc:
                    username, salt, dcc_hash = match_dcc.groups()
                    dcc_hashes[username] = f"$DCC2$10240#{salt}${dcc_hash}"

                # Match AES256 Kerberos keys
                match_aes256 = re.match(r"^([^:]+):aes256-cts-hmac-sha1-96:([a-fA-F0-9]+)$", line.strip())
                if match_aes256:
                    username, aes256_hash = match_aes256.groups()
                    aes256_hashes[username] = aes256_hash

                # Match AES128 Kerberos keys
                match_aes128 = re.match(r"^([^:]+):aes128-cts-hmac-sha1-96:([a-fA-F0-9]+)$", line.strip())
                if match_aes128:
                    username, aes128_hash = match_aes128.groups()
                    aes128_hashes[username] = aes128_hash

                # Match DES-CBC-MD5 Kerberos keys
                match_des = re.match(r"^([^:]+):des-cbc-md5:([a-fA-F0-9]+)$", line.strip())
                if match_des:
                    username, des_hash = match_des.groups()
                    des_hashes[username] = des_hash

        # Function to write hashes and display cracking command
        def write_hashes_and_display(hash_dict, hash_file, mapping_file, hash_type, hashcat_mode):
            if hash_dict:
                with open(hash_file, "w") as f_hash, open(mapping_file, "w") as f_map:
                    for username, hash in hash_dict.items():
                        f_hash.write(f"{hash}\n")
                        f_map.write(f"{username}:{hash}\n")
                print(f"✅ Found {len(hash_dict)} {hash_type} hashes. Saved to {hash_file} and {mapping_file}.")
                print(f"🔹 Crack with Hashcat:")
                print(f"   hashcat -m {hashcat_mode} -a 0 {hash_file} wordlist.txt")
                print(f"   hashcat -m {hashcat_mode} -a 3 {hash_file} ?a?a?a?a?a?a?a?a")
                print("")
            else:
                print(f"❌ No {hash_type} hashes found.")

        # Write and display Hashcat commands for each hash type
        write_hashes_and_display(ntlm_hashes, ntlm_file, ntlm_mapping_file, "NTLM", "1000")
        write_hashes_and_display(lm_hashes, lm_file, lm_mapping_file, "LM", "3000")
        write_hashes_and_display(dcc_hashes, dcc_file, dcc_mapping_file, "DCC2", "2100")
        write_hashes_and_display(aes128_hashes, aes128_file, aes128_mapping_file, "AES128", "19600")
        write_hashes_and_display(aes256_hashes, aes256_file, aes256_mapping_file, "AES256", "19700")
        write_hashes_and_display(des_hashes, des_file, des_mapping_file, "DES-CBC-MD5", "13100")

    except FileNotFoundError:
        print(f"❌ Error: File '{input_file}' not found. Please provide a valid path.")


def main():
    print("=======================================================")
    print("🛠️ Secretsdump Parsing Script")
    print("This script processes the output of secretsdump.py and extracts:")
    print("  - NTLM hashes")
    print("  - LM hashes")
    print("  - DCC2 hashes (Domain Cached Credentials)")
    print("  - AES128 and AES256 Kerberos keys")
    print("  - DES-CBC-MD5 Kerberos keys")
    print("Hashes are saved into separate files along with username mappings.")
    print("=======================================================")

    input_file = input("📄 Enter the path to the secretsdump output file: ").strip()

    if not os.path.exists(input_file):
        print(f"❌ Error: File '{input_file}' not found. Please check the path and try again.")
        return

    parse_secretsdump(input_file)


if __name__ == "__main__":
    main()
