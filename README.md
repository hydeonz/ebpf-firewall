```bash
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu/ -c bpf/xdp_block.c -o bpf/xdp_block.o
```