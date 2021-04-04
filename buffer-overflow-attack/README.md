# buffer-overflow-attack  
This repository contains programs coded for the lab assessment **(online-1)** on **buffer overflow attack**.  
SEED Ubuntu VM *(v16.04, 32bit)* provided by SEEDLabs is used as virtual lab environment.  
## navigation  
### `./buffer-overflow`  
- `call_shellcode.c` contains machine code for launching shell and is used to open up a terminal  
- `commands` contains basic commands  
- `exploit.py` contains machine code for launching shell and is used to create exploit  
- `stack.c` contains buffer-overflow vulnerability and is exploited using the exploit in `badfile` created by `exploit.py`  

### `./secret-function-call`  
- `commands` contains basic commands  
- `exploit.py`, `exploit_with_unknown_buffer_size.py`, and `exploit_without_segmentation_fault.py`  
  design and create exploits to call `secret_function()` from `buffer_overflow()`  
- `stack.c` contains buffer-overflow vulnerability and is exploited using the exploit in `badfile` created by `exploit.py`  
## guidelines  
### launching buffer overflow attack to open up a shell  
1. open up a terminal  
2. disable virtual address space layout randomization (ASLR) temporarily using either of the commands  
   `sudo sysctl -w kernel.randomize_va_space=0` or `sudo sysctl -q kernel.randomize_va_space`  
3. compile `./buffer-overflow/stack.c` and set **uid** to **root**  
   ```
   su root
   gcc -o stack_root -z execstack -fno-stack-protector stack.c
   chmod 4755 stack_root
   su seed
   ```  
4. design exploit by debugging `./buffer-overflow/stack.c` with **gnu debugger (gdb)**  
   ```
   gcc -z execstack -fno-stack-protector -g -o stack_dbg stack.c  # -g for adding debugging symbols
   gdb stack_dbg
   b buffer_overflow
   run
   p $ebp
   p &buffer
   p/d 0x<$ebp> - 0x<&buffer>
   quit
   ```  
   #### Do this step only if you need to redesign your exploit with stack addresses.  
5. prepare exploit in `./buffer-overflow/exploit.py` and write it to `badfile`  
   using the command `python3 exploit.py`  
6. run stack_root using the command `./stack_root`  
7. buffer overflow attack is successful!  

![alt text](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/buffer-overflow-attack/res/buffer-overlow-attack.png?raw=true)  

### launching buffer overflow attack to call `secret_function()`  
1. open up a terminal  
2. disable virtual address space layout randomization (ASLR) temporarily using either of the commands  
   `sudo sysctl -w kernel.randomize_va_space=0` or `sudo sysctl -q kernel.randomize_va_space`  
3. compile `./secret-function-call/stack.c`  
   ```
   gcc -o stack_root -z execstack -fno-stack-protector stack.c
   ```  
4. design exploit by debugging `./secret-function-call/stack.c` with **gnu debugger (gdb)**  
   ```
   gcc -z execstack -fno-stack-protector -g -o stack_dbg stack.c  # -g for adding debugging symbols
   gdb stack_dbg
   ...
   quit
   ```  
   #### Do this step only if you need to redesign your exploit with stack and function addresses.  
   #### You will find detailed commands in `./secret-function-call/commands`.  
5. prepare exploit in `./secret-function-call/exploit.py` and write it to `badfile`  
   using the command `python3 exploit.py`  
6. run stack_root using the command `./stack_root`  
   #### You may debug `./secret-function-call/stack.c` again to see things in details.  
7. buffer overflow attack is successful!  

![alt text](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/buffer-overflow-attack/res/secret-function-call.png?raw=true)  

## references  
- **set up SEED Ubuntu VM from this link:** https://seedsecuritylabs.org/lab_env.html  
