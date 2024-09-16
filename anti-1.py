import os
import hashlib  # Assuming you are using hashlib for md5 hashing

def md5_hash(filename):
    if not os.path.isfile(filename):
        print(f"File not found: {filename}")
        return None
    with open(filename, "rb") as f:
        # Read the file and calculate the MD5 hash
        file_hash = hashlib.md5()
        while chunk := f.read(8192):  # Read the file in chunks
            file_hash.update(chunk)
        return file_hash.hexdigest()  # Return the hexadecimal digest

def malware_checker(pathoffile):
    hash_malware_check = md5_hash(pathoffile)
    # Add your malware checking logic here
    return hash_malware_check  # Example return

# Call the malware_checker function with the correct path
#Add your File Path and type
print(malware_checker(r"Sample.txt,jpg"))