import subprocess
import os
import shutil
import hashlib
import threading
import time
import base64
import sys


CLI_PATH = "../cli/target/debug/cli"
PASSFILE_PATH = "../the_snapshot_secret"
SNAPSHOT_DIR = "/snapshot"
MOUNT_PATH = "/tmp/mnt"

# Paths to the images and backups
IMAGE_PATHS = {
    "ext4": "./ext4/ext4.img",
    "singlefilefs": "./singlefile_fs/sf.img",
}
BACKUP_PATHS = {
    "bfs": "./ext4/backup.img",
    "singlefilefs": "./singlefile_fs/backup.img",
}

NUM_THREADS = 4


def run_cmd(cmd):
    print(f"→ {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def mount_image(image_path, fs_type):
    os.makedirs(MOUNT_PATH, exist_ok=True)
    run_cmd(["mount", "-o", "loop", "-t", fs_type, image_path, MOUNT_PATH])


def umount_image():
    run_cmd(["umount", MOUNT_PATH])


def backup_image(image_path, backup_path):
    shutil.copy2(image_path, backup_path)


def activate_snapshot(image_path):
    run_cmd(
        [
            CLI_PATH,
            "--dev",
            os.path.abspath(image_path),
            "--passfile",
            PASSFILE_PATH,
            "activate",
        ]
    )


def deactivate_snapshot(image_path):
    run_cmd(
        [
            CLI_PATH,
            "--dev",
            os.path.abspath(image_path),
            "--passfile",
            PASSFILE_PATH,
            "deactivate",
        ]
    )


def find_snapshot_session(image_path):
    entries = os.listdir(SNAPSHOT_DIR)
    devname = os.path.basename(image_path)
    sessions = [e for e in entries if devname in e]
    assert (
        len(sessions) == 1
    ), f"Expected exactly one snapshot session for device '{devname}', found: {sessions}"
    return os.path.join(SNAPSHOT_DIR, sessions[0])


def restore_snapshot(image_path, session_path):
    run_cmd(
        [
            CLI_PATH,
            "--dev",
            os.path.abspath(image_path),
            "--session",
            session_path,
            "restore",
        ]
    )


def compare_images(original_path, restored_path):
    original_hash = sha256sum(original_path)
    restored_hash = sha256sum(restored_path)
    print("Original SHA256:", original_hash)
    print("Restored SHA256:", restored_hash)
    assert original_hash == restored_hash, "❌ Snapshot restore mismatch!"
    print("✅ Snapshot successfully restored")


# === WRITE OPERATIONS ===


def bfs_write():
    for i in range(5):
        with open(f"{MOUNT_PATH}/ft_{i}.txt", "w") as f:
            f.write(f"bfs_data_{i}")

    def writer(id):
        for i in range(5):
            with open(f"{MOUNT_PATH}/thread_{id}_{i}", "wb") as f:
                content = os.urandom(5)
                # if i % 2 == 0:
                #     # We avoid base64 encoding every time to keep some data highly random, making compression not effective.
                #     # This helps test the fallback path where compression is not performed and the original data is copied as-is.
                #     content = base64.b64encode(content)

                f.write(content)
                time.sleep(0.2)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def singlefilefs_write():
    target_file = os.path.join(MOUNT_PATH, "the-file")

    def writer(content, offset, length):
        try:
            fd = os.open(target_file, os.O_RDWR)
        except OSError:
            print(f"❌ Error opening file {target_file}")
            sys.exit(1)

        try:
            os.lseek(fd, offset, os.SEEK_SET)
        except OSError:
            print(f"❌ Error seeking in file {target_file}")
            os.close(fd)
            sys.exit(1)

        data = content
        to_write = len(data)
        while to_write > 0:
            try:
                ret = os.write(fd, data)
            except OSError:
                print(f"❌ Error writing to file {target_file}")
                os.close(fd)
                sys.exit(1)

            data = data[ret:]
            to_write -= ret

        os.close(fd)

    for i in range(5):
        content = os.urandom(4096)
        if i % 2 == 0:
            # We avoid base64 encoding every time to keep some data highly random, making compression not effective.
            # This helps test the fallback path where compression is not performed and the original data is copied as-is.
            content = base64.b64encode(content)

        writer(content, 4096 * i, len(content))


# === MAIN TEST LOGIC ===


def run_test_for_fs(fs_type):
    print(f"\n\n===== 🔍 Testing {fs_type} filesystem =====")
    image_path = IMAGE_PATHS[fs_type]
    backup_path = BACKUP_PATHS[fs_type]

    print("🔧 Mounting and populating initial state...")
    mount_image(image_path, fs_type)

    if fs_type == "bfs":
        bfs_write()  # initialization
    elif fs_type == "singlefilefs":
        singlefilefs_write()  # initialization
    else:
        raise ValueError("Unsupported FS_TYPE")

    print("🔧 Unmounting...")
    umount_image()

    print("📀 Saving image backup...")
    backup_image(image_path, backup_path)

    print("📸 Activating snapshot...")
    activate_snapshot(image_path)

    print("✍️ Remounting and applying MODIFICATIONS...")
    mount_image(image_path, fs_type)

    if fs_type == "bfs":
        bfs_write()
    elif fs_type == "singlefilefs":
        singlefilefs_write()

    time.sleep(0.5)

    print("🔧 Unmounting...")
    umount_image()

    print("📸 Deactivating snapshot...")
    deactivate_snapshot(image_path)

    print("♻️ Restoring snapshot...")
    session = find_snapshot_session(image_path)
    restore_snapshot(image_path, session)

    print("🔍 Comparing restored image with backup...")
    compare_images(backup_path, image_path)


# === ENTRY POINT ===

if __name__ == "__main__":
    # Take as input the filesystem type to test
    if len(sys.argv) != 2:
        print("Usage: python snapshot_test.py <fs_type>")
        print("fs_type: singlefilefs or bfs")
        sys.exit(1)

    fs_type = sys.argv[1]
    if fs_type not in IMAGE_PATHS:
        print(f"Unsupported fs_type: {fs_type}")
        sys.exit(1)

    run_test_for_fs(fs_type)
