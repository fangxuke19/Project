make clean;
make;
rmmod sniffer_mod.ko;
insmod sniffer_mod.ko;
mknod sniffer.dev c 251 0;
