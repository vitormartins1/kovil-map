import os
import urllib.request
import zipfile
import shutil

TOOLS_DIR = os.path.join(os.getcwd(), "tools")
HASHCAT_URL = "https://hashcat.net/files/hashcat-6.2.6.zip"

def download_and_extract(url, dest_folder):
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    
    filename = url.split('/')[-1]
    filepath = os.path.join(dest_folder, filename)
    
    print(f"Downloading {filename}...")
    urllib.request.urlretrieve(url, filepath)
    
    print("Extracting...")
    with zipfile.ZipFile(filepath, 'r') as zip_ref:
        zip_ref.extractall(dest_folder)
    
    print("Done.")

if __name__ == "__main__":
    download_and_extract(HASHCAT_URL, TOOLS_DIR)