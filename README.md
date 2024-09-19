![image](https://github.com/user-attachments/assets/b2b96d36-758c-47f9-b7eb-f34d274152e3)


# CoffeeCantelope
Source code examples for a deprecated "DLL Memory Mapped Path Inclusion framework."


* Within `dev/test` you can find the related early source files for the initial development process phase.
* CC would have utilized a command and control based infrastructure through IPC (Inter Process communication).
* It would have used an in-house developed "In memory phishing template generation" feature to chain the initial dropper process.
* NOTE: None of the `src/*.c` files have been uploaded publicly to Github as open source at this current point in time.

#### Full excerpt from `C8H10N4O2.txt`:
### CAFFEINE.txt
==============

DLL Memory Mapped Path Inclusion framework.

Command and Control through IPC.

### ASIDE
=======

In memory phishing template generation?
Is it possible to "reprogram" USB devices to act as security keys?
Like a YubiKey?
    - Setup password for the user through application
    - Have separate application to generate hardware based 
      unique registration codes?

Obtain memory layout of target process.
Identify virtual memory pages:
    These are segments within the MAX bounds register value of the virtual address space.

    Identify the VPN (Virtual Page Number) along with the PFN (Physical Frame Number) to identify 
    where in Physical memory this information begins and ends.

Identify Memory paging protections on each virtual page frame.

Is writable?
    * How much space can be allocated by the heap allocator within 
      that VPF?

Establish channel:

    1. How to communicate?
        - Security implications
            * Encryption | Obfuscation methods

        - Detection rate/response time?
            - CPU trap timer interrupts
            - Process priority?
            - Measure execution to execute within alloted time slice (scheduling quantum)?

              * Execution time = decrypted memory instruction RT (Run Time).

    * OPTIONS 
    =========

    1. Shared Pipes (IPC)
        C@ -> https://learn.microsoft.com/en-us/windows/win32/ipc/pipes

        - Anonymous Pipe
            An anonymous pipe is an unnamed, one-way pipe that typically transfers
            data between a parent process and a child process.

            Just a named pipe with a unique name with imposed restrictions.

        - Named Pipe (WINNER)

        - DLL could be XOR encrypted in memory, after NamedPipe is setup by 
            the other remote process that was DLL injected into.

            Naming Conventions
            ==================
            !START

                @PROC1 = PROC1
                    INF: PROC1 is the "initializer process" that will first inject 
                        a remote thread into a memory region that has been previously 
                        allocated with VirtualAllocEx()

                        The first process injected into is also known as the "dummy process"
                        such a process is only used to setup a NamedPipe server so that the 
                        actual targeted process that is being inspected can establish a channel
                        as the pipe client and obtain the key to the encrypted memory region before decrypting it 
                        and calling LoadLibraryA from a function pointer to kernel32.dll

                        ASIDE
                        =====

                        Possibly get the uptime of the current process and determine 
                        if the encryption key should be sent as a whole chunk of data 
                        or if it should be sent in chunks with fixed time intervals 
                        in between before sending the rest of the data

                        CRUX 
                        ----
                            1. How does the pipe client communicate with PROC1?
                                - Private region of memory?
                                - Setting a specific bit in memory?
                            
                            2. Communicate directly through the NamedPipe?

                            3. How would PROC1 hide it's presence in memory?
                                - Spawn as a legitimate looking child process of its 
                                  host process?

                                    - child process operates as a pipe server 
                                    - modify current process permissions for SE_DEBUG

                                    - When a signal is sent to the child process, kill the 
                                      parent process ExitProcess()

                                - Hijack execution flow of the host process and kill the 
                                  parent process and any child processes associated with it
                                  before injecting into the virtual memory address space of the 
                                  target process (host process)

            PROC1 => DLL INJECT => PROC2
            PROC1 => Sets up NamedPipe 
            PROC2 => Pipe Client => (PROC1) NamedPipe server

            NOTE: PROC2 would be loading an encrypted dll from memory via PROC1's 
                  virtual address space, this encrypted dll would then be mapped to the 
                  calling processes address space and subsequently loaded thereafter.

                  - This encrypted DLL would be loaded over the NamedPipe

            PROC1 & PROC2 exchange secrets to establish identity.

                - PROC1 can load encrypted DLL's in its own virtual memory address space 
                - PROC2 can then query to obtain a list of loaded DLLs
                    - this list will return the pointer to the virtual start address to be loaded
                      along with an id to "identify" the purpose of the dll file

                      CRUX 
                      ====

                      1. Should this DLL be "packed" (compressed and encrypted)?
                      2. Have separate tool to construct compressed and encrypted DLL's?

                      3. How to store structure in memory that ID's DLL's available to load?
                         - will each DLL encrypted module have a descriptor along with it?

// NOTE: store as file id?
# CCMMPIF

Should be able to allocate space inside of system processes in user space
and utilize various techniques to determine which processes allow memory mapping a DLL.
these processes should be tagged and stored, further operations should be 
executed on them.
