# Linux Kernel Block Device Snapshot Subsystem

![Snapshot Subsystem](media/image.jpg)

This project provides a **Linux kernel module** for managing **block device snapshots**. It allows users to register block devices (e.g., `/dev/sdX`) that host mounted file systems and capture their content in a **Copy-on-Write (CoW)** fashion. The subsystem operates on **mount cycles**, enabling restoration of a device to its **pre-mount state**.

## Key Features

- Copy-on-Write snapshotting
- Restore device to its pre-mount state once it gets unmounted (of only modified blocks)
- Supports both **regular block devices** and **loop devices**
- Dual interface for user interaction: **syscalls** (x86 only) and **ioctl**
- Tested on both **x86** and **ARM** architectures
- Includes:
  - **User-level C library** (`cli/user_lib/`) supporting both syscall and ioctl APIs
  - **Rust-based CLI tool** for device management and snapshot restoration

## Interfaces

From a high level to manage devices within the snapshot subsystem there are two main interfaces:

- `activate_snapshot(char *devname, har *password)`
- `deactivate_snapshot(char *devname, char *password)`

Once the service is active for a device, and the device is mounted, the subsystem creates a new snapshot session and starts to intercept write operations on the mounted file system.

### Syscalls (x86 only)

Activation and deactivation syscalls provide an interface for interacting with the snapshot subsystem.

### IOCTL (cross-platform)

An in-kernel **character device** at `/dev/snap` allows user interaction via ioctl commands. The device supports ioctl operations for activation and deactivation of snapshots.

## User Library & CLI Tool

- **C Library (`cli/user_lib/`)**: Offers an abstraction over syscall/ioctl to facilitate easy integration into user applications.
- **Rust CLI Tool**: A command-line interface that allows:
  - Device snapshot activation and deactivation
  - Restoration of snapshot state

## 🧰 Install Dependencies

Before proceeding with the tests and a manual deployment, make sure your system has the necessary tools installed:

### 1. Build tools, Filesystem Utilities and the zlib development package

Install `e2fsprogs` to use tools like `mkfs.ext4`, the zlib package for compression functions and python for executing tests.

```bash
sudo apt update
sudo apt install build-essential e2fsprogs zlib1g-dev python3
```

### 2. Rust Toolchain

Install Rust and Cargo (Rust's package manager and build tool) for the cli tool:

```bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
```

Verify installation:

```bash
cargo --version
```

### 3. Build CLI Tool

Navigate to the CLI directory and build the CLI tool:

```bash
cd cli
cargo build
cd ..  # Return to the root directory
```

## ✅ Testing Guide

Two main variants of the subsystem exist: a stable V1 version and an experimental V2 version. The V1 is fully spec-compliant and can be tested on the `singlefile_fs` in the tests directory. The V2 aims to support all file systems and comes with some trade-offs and less stability.

### 🧪 Test 1: `singlefile_fs`

This test uses a simplified file system (`tests/singlefile_fs`) and targets the stable V1 version of the snapshot module.

### Key Characteristics

- Hooks both `vfs_write` and buffer cache operations (to work with the `buffer_head`).
- Intercepts writes and copies the corresponding block before it is modified.
- Fully supports the `singlefile_fs` test environment.
- May not support other file systems.

### Run the Test

```bash
make test_singlefile_fs
```

### 🧪 Test 2: ext4 with the Experimental V2 version

This test evaluates the experimental V2 snapshot module version, which targets general-purpose file systems like ext4.

### Key Characteristics

- Hooks into the block layer via `submit_bio` to intercept write requests.
- Cannot rely on `mount_bdev`, so session activation occurs at the first `vfs_write` (not using `submit_bio` to first activate the snapshot session).

### Issues: Future Works

- Early bio submissions before the first `vfs_write` are not captured.
- Lacks taking references of bio's components to prevent unmounting during write operations (not sure it can be done).
- User must be cautios to when registering, mounting and unmounting the device to avoid issues.
- On rare cases tests could have an undefined behaviour.

**WARNING**: This test has been mainly conducted on an ARM based architecture.

### Run the Test

```bash
make test_ext4
```

## ⚙️ Manual Deployment

### On x86

Build and deploy the entire project using:

```bash
make all
make load       # Loads the V1 snapshot module version, the singlefile_fs driver and a utility module for the system call table hack (`the_usctm`)
```

The loaded snapshot module includes both `syscall` and `ioctl` support.

### On both ARM and x86

You can also build and load modules manually (see all Makefile targets).

Build the modules:

```bash
make build_bdev_snapshot
make build_testing_fs
```

Load the modules:

```bash
make load_bdev_snapshot_ioctl_v1   # Or another variant in the Makefile
make load_testing_fs_driver
```

## 📸 Snapshot management

For serveral commands you will need root priviledges, so execute commands using `sudo`.

Or to ease the overall process just login to your root account by running:

```bash
sudo su
```


### 1. Create Device Files

To test the manual deployment you can prepare disk image files for both filesystems by running:

```bash
make build_fs_environment
```

This will create:

- `tests/singlefile_fs/sf.img`
- `tests/ext4/ext4.img`

### 2. Activate Snapshot

To activate the snapshot service for a device through the cli tool you can run:

```bash
cd cli
./target/debug/cli --dev $PWD/../tests/singlefile_fs/sf.img --passfile ../the_snapshot_secret activate
cd ..
```

### 3. Mount the Filesystem

To create a new snapshot session and start to monitor the file system you can run:

```bash
make mount_testing_fs
```

The filesystem is mounted on `/tmp/mnt`. The only file is `the-file`.

### 4. Perform Writes

To modify the file, run a simple user space executable in `tests/singlefile_fs/user`:

```bash
cd tests/singlefile_fs/user
./user /tmp/mnt/the-file 10 "Just some dummy content to modify the singlefile_fs file"
cd ../../..
```

### 5. Unmount the Filesystem

By unmounting the filesystem you terminate the snapshot session being created

```bash
make umount_fs
```

### 6. Restore Snapshot

First, get the snapshot session directory created by the subsystem at: `/snapshot/<dev_name>_<mount_timestamp>`.

Then run:

```bash
cd cli
./target/debug/cli --dev $PWD/../tests/singlefile_fs/sf.img --session <session_directory> restore
```

### 7. Deactivate the Snapshot

For the testing device run:

```bash
./target/debug/cli --dev $PWD/../tests/singlefile_fs/sf.img --passfile ../the_snapshot_secret deactivate
cd ..
```

### 7. Unload the Modules

To unload the modules run:

```bash
make unload_bdev_snapshot
make unload_testing_fs_driver
```

---
