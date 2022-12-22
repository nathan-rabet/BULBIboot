# BULBIboot

BULBIboot is an aarch64 bootloader for Linux. It is designed to be simple and easy to use.

Also, BULBIboot is ~~better than pikaboot~~.

![BULBIboot](images/logo.png)

## Usable features

- **Boot Linux kernel** at EL1, EL2 & EL3
- **Download a kernel for emrgency** booting via serial
- **Dump some memory** regions and print them to console
- **Test the memory efficiency** (memtest)

## Hidden but useful features

- Secure "preboot system"
- Bootloader **signature verification**
- Bootloader **encryption**
- **`-O3` optimization** level
- **CRC32 verification** of the kernel during boot and ermgency boot download

## How to build & boot

### Install the dependencies

First, you need to install the dependencies. You can do it with the following command:

```Makefile
make dependencies
```

> Note that this routine is compatible with apt, pacman and dnf package managers.

### Build the images

To build the images (encrypted and clear), just run the following command:

```Makefile
make images
```

> Running `make` also do the same trick.

### Booting with QEMU

To boot the bootloader with QEMU, just run the following command:

```Makefile
make boot
```

> If you want to boot the bootloader with QEMU with a GDB-stub listener, just run `make boot_gdb`
> > If you are using VSCode, you can use the `.vscode/launch.json` file to debug the bootloader with GDB.

Then, when QEMU is running, you will notice a path to something like `/dev/pts/<n>` (where `<n>` is a number). This is the path to the serial port. You can use it to connect to the bootloader.

If you want to use the serial port with `screen`, you can use the following command:

```bash
screen /dev/pts/<n>
```

## How to use

See the [HOWTO.md](HOWTO.md) for more details.

## Work in progress

Here is a list of some features that I worked on, but I didn't finish:

- Kernel signature verification
  - I worked on it, but I didn't finish it, because it need a position-independent code (PIC) compilation to work.

- Multiple boards support
  - I worked on it, but I didn't finish it, because I worked on an Orange Pi and Vexpress board, which are aarch32 boards.

## License

BULBIboot is licensed under the Beerware license. See the [LICENSE](LICENSE) file for more details.
