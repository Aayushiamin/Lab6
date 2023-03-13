import requests
import hashlib
import subprocess
import os


def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()
    print(f'The expected SHA256 hash value of the VLC installer is {expected_sha256}')
     
    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()
    
    # Verify the integrity of the downloaded VLC installer by comparing the
    actual_sha256 = hashlib.sha256(installer_data).hexdigest()
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    lines = response.text.split('/n')

    for line in lines:
        if line.endwith("vlc-3.0.18-win64.exe"):
            sha256_hash = line.split()[0]
    return sha256_hash

def download_installer():
    url = "http://download.videolan.org/pub/videolan/vlc/3.0.18/win64/"
    response = requests.get(url, stream = True)

    return response.content

def installer_ok(installer_data, expected_sha256):
    computed_sha256 = hashlib.sha256(installer_data).hexdigest()

    return computed_sha256 == expected_sha256

def save_installer(installer_data):
    if actual_sha256 != expected_sha256:
        raise Exception('Downloaded installer has incorrect SHA-256 hash value')
    
    installer_path = "vlc-3.0.18-win64.exe"
    with open(installer_path, "wb") as f:
        f.write(installer_data)

    return installer_path

def run_installer(installer_path):
    subprocess.run([installer_path, "/s"], check = True)

    return
    
def delete_installer(installer_path):
    os.remove(installer_path)

    return

if __name__ == '__main__':
    main()