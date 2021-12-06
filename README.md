# Packet Batch (AF_XDP)
## Description
This is a special version of Packet Batch that utilizes `AF_XDP` [sockets](https://01.org/linuxgraphics/gfx-docs/drm/networking/af_xdp.html) instead of `AF_PACKETv3` (which is what the standard version uses). I recommend this version over the standard version, but you must keep in mind the following.

1. AF_XDP sockets requires a **more recent** Linux kernel.
1. The TCP `usesocket` setting is **NOT** available in this version due to cooked sockets not being a thing within AF_XDP.

The above is why we aren't utilizing AF_XDP sockets in the standard version.

There is also additional command line usage with this program.

From the benchmarks I've concluded on my home server running Proxmox VMs, AF_XDP sockets send around 5 - 10% more packets per second than the standard version and the amount of packets per second it is sending is a lot more consistent (regardless of the batch size option explained below). I won't have solid benchmarks until I perform these tests on full dedicated hardware which should happen in early 2022.

## Additional Command Line Usage
The additional command line arguments are supported.

```
--queue => If set, all AF_XDP/XSK sockets are bound to this specific queue ID.
--nowakeup => If set, all AF_XDP/XSK sockets are bound without the wakeup flag.
--sharedumem => If set, all AF_XDP/XSK sockets use the same UMEM area.
--batchsize => How many packets to send at once (default 1).
--forceskb => If set, all AF_XDP/XSK sockets are bound using the SKB flag instead of DRV mode.
--zerocopy => If set, all AF_XDP/XSK sockets are attempted to be bound with zero copy mode.
--copy => If set, all AF_XDP/XSK sockets are bound with copy mode.
```

**NOTE** - The **batch size** indicates how many packets to send at the same time, but this is the **same** packet data. This may or may not speed up performance, but personally I didn't see much of an impact.

**NOTE** - By default, each socket is created in a separate thread specified in the YAML config and is bound to a separate queue ID (incremented by 1). With that said, shared UMEM is not supported by default and each socket has its own UMEM area. The XDP wakeup flag is also specified by default which should improve performance.

## Building And Installing
Building and installing this project is fairly easy and just like the standard version. It includes building the Packet Batch Common repository which requires [libyaml](https://github.com/yaml/libyaml). As long as you use the `--recursive` flag with `git`, it should retrieve all of the required submodules automatically located in the `modules/` directory. Otherwise, you will need to go into the Common repository and execute the `git submodule update --init` command. We use `make` to build and install the application.

```bash
# Clone this repository along with its submodules.
git clone --recursive https://github.com/Packet-Batch/PB-AF-XDP.git

# Install build essentials/tools and needed libaries for LibYAML.
sudo apt install build-essential clang autoconf libtool

# Install LibELF for BPF.
sudo apt install libelf-dev

# Change the current working directory to PB-AF-XDP/.
cd PB-AF-XDP/

# Make and install (must be ran as root via sudo or root user itself).
sudo make
sudo make install
```

### Installation Video!
[![Click here to watch!](https://g.gflclan.com/linux-laptop-bigmode-23-14-42.png)](https://www.youtube.com/watch?v=2vWJUgsbbIM)

After installing, the executable is copied to the `/usr/bin/` directory which should be included in your `$PATH`. Therefore, you may use the application globally (in any directory).

For example.

```bash
pcktbatch -c /path/to/pcktbatch.yaml
```

## Credits
* [Christian Deacon](https://github.com/gamemann)