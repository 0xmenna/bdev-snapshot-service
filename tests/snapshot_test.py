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


IMAGE_PATHS = {
    "ext4": "./ext4/ext4.img",
    "singlefilefs": "./singlefile_fs/sf.img",
}
BACKUP_PATHS = {
    "ext4": "./ext4/backup.img",
    "singlefilefs": "./singlefile_fs/backup.img",
}

NUM_THREADS = 4


def run_cmd(cmd, quiet=False):
    print(f"→ {' '.join(cmd)}")
    if quiet:
        with open(os.devnull, "w") as devnull:
            subprocess.run(
                cmd,
                check=True,
                stdout=devnull,
                stderr=devnull,
            )
    else:
        subprocess.run(cmd, check=True)


def wait_for_log():
    time.sleep(1.5)


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
        ],
        quiet=True,
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
        ],
        quiet=True,
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
        ],
        quiet=True,
    )


def compare_images(original_path, restored_path):
    original_hash = sha256sum(original_path)
    restored_hash = sha256sum(restored_path)
    print("Original SHA256:", original_hash)
    print("Restored SHA256:", restored_hash)
    assert original_hash == restored_hash, "❌ Snapshot restore mismatch!"
    print("✅ Snapshot successfully restored")


def record_file_hashes():
    """Record SHA256 hashes of all files in the mounted filesystem"""
    hashes = {}
    for root, _, files in os.walk(MOUNT_PATH):
        for file in files:
            file_path = os.path.join(root, file)
            hashes[file_path] = sha256sum(file_path)
    return hashes


def verify_file_hashes(original_hashes):
    """Verify current file hashes match the originally recorded ones"""
    for file_path, original_hash in original_hashes.items():
        if not os.path.exists(file_path):
            print(f"❌ File missing: {file_path}")
            return False

        current_hash = sha256sum(file_path)
        if current_hash != original_hash:
            print(f"❌ Content changed: {file_path}")
            print(f"  Original: {original_hash}")
            print(f"  Current:  {current_hash}")
            return False

    print("✅ All files match their original content")
    return True


# === WRITE OPERATIONS ===


def ext4_write():
    def writer(id):
        for i in range(5):
            with open(f"{MOUNT_PATH}/thread_{id}_{i}", "wb") as f:
                content = os.urandom(4096 * (i + 1))
                if i % 2 == 0:
                    # We avoid base64 encoding every time to keep some data highly random, making compression not effective.
                    # This helps test the fallback path where compression is not performed and the original data is copied as-is.
                    content = base64.b64encode(content)

                f.write(content)
                f.flush()
                os.fsync(f.fileno())

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def singlefilefs_write():
    target_file = os.path.join(MOUNT_PATH, "the-file")

    def writer(i):
        content = os.urandom(4096)
        if i % 2 == 0:
            # We avoid base64 encoding every time to keep some data highly random, making compression not effective.
            # This helps test the fallback path where compression is not performed and the original data is copied as-is.
            content = base64.b64encode(content)

        offset = 4096 * i

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

        to_write = len(content)
        while to_write > 0:
            try:
                ret = os.write(fd, content)
            except OSError:
                print(f"❌ Error writing to file {target_file}")
                os.close(fd)
                sys.exit(1)

            content = content[ret:]
            to_write -= ret

        os.close(fd)

    # First write consecutive blocks sequentially
    for i in range(5):
        writer(i)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# === MAIN TEST LOGIC ===


def run_test_for_fs(fs_type):
    try:
        print(f"\n\n===== 🔍 Testing {fs_type} filesystem =====")
        image_path = IMAGE_PATHS[fs_type]
        backup_path = BACKUP_PATHS[fs_type]

        print("🔧 Mounting and populating initial state...")
        wait_for_log()

        mount_image(image_path, fs_type)

        if fs_type == "ext4":
            ext4_write()  # initialization
            # Record file hashes for later comparison
            original_hashes = record_file_hashes()
        elif fs_type == "singlefilefs":
            singlefilefs_write()  # initialization
        else:
            raise ValueError("Unsupported FS_TYPE")

        print("🔧 Unmounting...")
        wait_for_log()

        umount_image()

        if fs_type == "singlefilefs":
            print("📀 Saving image backup...")
            wait_for_log()

            backup_image(image_path, backup_path)

        print("📸 Activating snapshot...")
        wait_for_log()

        activate_snapshot(image_path)

        print("✍️ Remounting and applying MODIFICATIONS...")
        wait_for_log()

        mount_image(image_path, fs_type)

        if fs_type == "ext4":
            ext4_write()
        elif fs_type == "singlefilefs":
            singlefilefs_write()

        print("🔧 Unmounting...")
        wait_for_log()

        umount_image()

        print("📸 Deactivating snapshot...")
        wait_for_log()

        deactivate_snapshot(image_path)

        print("♻️ Restoring snapshot...")
        wait_for_log()

        session = find_snapshot_session(image_path)
        restore_snapshot(image_path, session)

        print("🔍 Verifying restore...")
        wait_for_log()

        if fs_type == "ext4":
            # Mount and verify file contents
            mount_image(image_path, fs_type)
            if not verify_file_hashes(original_hashes):
                raise AssertionError(
                    "Snapshot restore verification failed - file hashes don't match!"
                )
            umount_image()
        else:
            # For singlefilefs, compare images
            compare_images(backup_path, image_path)

        print(f"\n🎉 Test for {fs_type} filesystem PASSED successfully!")

    except Exception as e:
        print(f"\n❌❌❌ Test for {fs_type} filesystem FAILED! ❌❌❌")
        print(f"Reason: {str(e)}")
        print(f"Exception type: {type(e).__name__}")


# === ENTRY POINT ===

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python snapshot_test.py <fs_type>")
        print("fs_type: singlefilefs or bfs")
        sys.exit(1)

    fs_type = sys.argv[1]
    if fs_type not in IMAGE_PATHS:
        print(f"Unsupported fs_type: {fs_type}")
        sys.exit(1)

    run_test_for_fs(fs_type)
