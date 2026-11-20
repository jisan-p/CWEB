# Installation

### Building and Installing

CWEB is designed for modern Linux environments and has been validated across major enterprise distributions:

- **Debian** (11 Bullseye, 12 Bookworm)
- **Ubuntu** (22.04 LTS, 24.04 LTS)
- **Arch Linux / CachyOS**

Clone the repository from GitHub:

```bash
git clone https://github.com/saadalabeed/cweb.git
cd cweb
```

#### Pre-Compilation Step (Debian / Ubuntu)

On Debian and Ubuntu systems, PostgreSQL client headers (`libpq-fe.h`) are packaged inside a subdirectory (`/usr/include/postgresql/`). Run this symlink command before compiling to ensure the header files are discoverable:

```bash
sudo ln -svf /usr/include/postgresql/* /usr/include/
```

#### Compiling and Installing

Compile the shared library (`libcweb.so`) and install it into system paths:

```bash
make
sudo make install
```

This compiles all engine modules into `libcweb.so`, copies the shared object to `/usr/lib/`, copies the primary header `cweb.h` to `/usr/include/`, and updates the system dynamic linker cache via `ldconfig`.

To clean intermediate object files after installation:

```bash
make clean
```

---

### Base Requirements

CWEB relies on modern Linux kernel primitives and a minimal set of high-performance system libraries:

- **Linux Kernel 5.7+**: Required for `io_uring_prep_splice`.
  *(Note: Linux Kernel 5.19+ is recommended to leverage lock-free `IORING_SETUP_SINGLE_ISSUER` and cooperative task running `IORING_SETUP_COOP_TASKRUN`).*
- **C Compiler**: GCC 9+ or Clang 10+ with GNU99 support (`-std=gnu99 -D_GNU_SOURCE`).
- **liburing**: Linux `io_uring` user-space interface library.
- **libpq**: PostgreSQL C client library. PostgreSQL 14+ is recommended for native Pipeline Mode support (`PQenterPipelineMode`, `PQpipelineSync`).
- **libseccomp**: High-level platform library for Linux Seccomp-BPF system call filtering.

---

### Distribution Packages

Install the required build tools and libraries using your distribution's package manager:

#### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y build-essential liburing-dev libpq-dev libseccomp-dev
sudo ln -sf /usr/include/postgresql/* /usr/include/
```

> **Note for Debian 11 (Bullseye):**  
> Debian 11 ships with older packages. Make sure to use `libpq-dev` with Pipeline Mode support (from `bullseye-pgdg` or backports) and compile with `-std=gnu99` to support `liburing 0.7` barrier macros.

#### Arch Linux / CachyOS

```bash
sudo pacman -S base-devel liburing postgresql-libs libseccomp
```

#### Fedora / RHEL 9+

```bash
sudo dnf install -y gcc make liburing-devel libpq-devel libseccomp-devel
```

---

### Build Options & Customization

CWEB's `Makefile` supports several configuration overrides:

- **Compiler Selection (`CC`)**:
  ```bash
  make CC=clang
  ```

- **Debug Build (`CFLAGS`)**:
  By default, CWEB compiles with high-level optimizations (`-O3`). To build with debugging symbols and disable optimizations:
  ```bash
  make CFLAGS="-Wall -Wextra -std=gnu99 -g -O0 -fPIC -D_GNU_SOURCE"
  ```

- **Custom Installation Prefix**:
  If installing to a non-standard library directory (e.g., `/usr/local/lib`):
  ```bash
  sudo cp libcweb.so /usr/local/lib/
  sudo cp include/cweb.h /usr/local/include/
  sudo ldconfig
  ```

---

### Verifying the Installation

To verify that CWEB has been installed correctly:

1. Check that the shared library and headers are present:
   ```bash
   ls -l /usr/lib/libcweb.so
   ls -l /usr/include/cweb.h
   ```

2. Create a minimal test application (`test_cweb.c`):
   ```c
   #include <cweb.h>

   HandlerState hello(CwebContext* ctx) {
       send_text(ctx, 200, "CWEB is operational!\n");
       return DB_DONE;
   }

   int main(void) {
       insert_route(GET, "/", hello);
       return cweb_run_server(8080, NULL, 0);
   }
   ```

3. Compile and execute:
   ```bash
   gcc test_cweb.c -lcweb -o test_cweb
   sudo ./test_cweb
   ```

   *(Note: `sudo` is required because the master process drops privileges to `nobody:nobody` and raises `RLIMIT_MEMLOCK` limits).*

4. In a separate terminal, test the endpoint:
   ```bash
   curl http://127.0.0.1:8080/
   ```

---

### Uninstallation

To remove CWEB from your system:

```bash
sudo rm -f /usr/lib/libcweb.so
sudo rm -f /usr/include/cweb.h
sudo ldconfig
```
