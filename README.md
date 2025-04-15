```bash
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu/ -c bpf/xdp_block.c -o bpf/xdp_block.o
```
TODO: 
1. необходимо добавить разрешающий трафик (к тому же, чтобы он был в приоритете).
2. рефакторинг кода, вынос дублей.