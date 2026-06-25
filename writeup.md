
## Get Kernal32.dll base
### Inspecting the TEB

The Thread Environment Block (TEB) structure describes the state of a thread.

`ProcessEnvironmentBlock`

A pointer to the [PEB](https://learn.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-peb) structure that contains information for the process as a whole.


`Peb` of x32 program located in the `fs` segment at offset `0x30`:
![](pics/Pasted%20image%2020260616071914.png)

`Peb` of x64 program located in the `gs` segment at offset `0x60`:
![](pics/Pasted%20image%2020260616072144.png)

### Inspecting PEB
I am interested in the `LDR` because it contains A pointer to a [PEB_LDR_DATA](https://learn.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-peb_ldr_data) structure that contains information about the loaded modules for the process.

`Ldr` is located at offset `0xc` in x32:
![](pics/Pasted%20image%2020260616072933.png)



`Ldr` is located at offset `0x18` in x64:
![](pics/Pasted%20image%2020260616072815.png)


### Inspecting the loaded modules

The head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an **LDR_DATA_TABLE_ENTRY** structure.

offset of `InMemoryOrderModuleList` in x32:
![](pics/Pasted%20image%2020260616080802.png)

offset of `InMemoryOrderModuleList` in x64:
![](pics/Pasted%20image%2020260616080419.png)
### First module

Main Executable module
![](pics/Pasted%20image%2020260616081243.png)

### Second module

ntdll.dll
![](pics/Pasted%20image%2020260616081040.png)

### Third module (TARGET)

kernal32.dll That is our target in order to get address of `LoadLibrary` on the fly without hardcoding it.

![](pics/Pasted%20image%2020260616081333.png)

### Obtain the DLL base

DLL_BASE at offset `0x18` in x32:
![](pics/Pasted%20image%2020260616085515.png)

DLL_BASE at offset `0x18` in x64:
![](pics/Pasted%20image%2020260616085449.png)

### Misalignement

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

Since the `InMemoryOrderLinks` is not the first memeber in the struct parsing the address to this struct will result in misaligned structure making the offsets completely wrong. Solution is shift the address of `InMemoryOrderLinks.flink` by 0x10 to compensate.

### Result

I got the right dll_base address for `kernal32.dll`

![](pics/Pasted%20image%2020260618144110.png)

![](pics/Pasted%20image%2020260616090631.png)


## Get to Export list

```
RVA of PE signature -> 0x3c
```
![](pics/Pasted%20image%2020260616135104.png)

Verify
![](pics/Pasted%20image%2020260616135142.png)


```
RVA of Export Table (relative)-> 180 - f8 = 0x88
```
![](pics/Pasted%20image%2020260616135546.png)

```
Relative offset calculations

9b8d0 -> Export Table
9b8dc -> Name of dll -> 9b8dc - 9b8d0 = 0x0c
9b8e4 -> number of functions -> 9b8e4 - 9b8d0 = 0x14
9b8ec -> addresses of functions -> 9b8ec - 9b8d0 = 0x1c
9b8f0 -> Address of names -> 9b8f0 - 9b8d0 = 0x20
9b8f4 -> address of Names Ordinals -> 9b8f4 - 9b8d0 = 0x24
```
![](pics/Pasted%20image%2020260618074003.png)

## Used Offsets to reach the DLL_BASE
```asm
; zero out the register
	xor rax, rax

	; get the PEB address
	mov rax, [gs:0x60]

	; get Ldr address
	mov rcx, [rax + 0x18]

	; get InMemoryOrderModuleList address 
	mov rsi, [rcx + 0x20]

	; get ntdll module
	LODSQ
	xchg rax, rsi ; exchange values
	
	; get kernal32 module
	LODSQ

	; align the structure by 0x10
	sub rax, 0x10

	; get DLL base
	mov rax, [rax + 0x30]

	; read e_lfanew offset
	xor rcx, rcx
	mov ecx, DWORD [rax + 0x3c]
	
	; calculate address for signature (dll_base + e_lfanew_value) 
	lea rdx, [rax + rcx]
	
	; read Export table RVA
	mov ecx, [rdx + 0x88]
	
	; calculate address for Export table (dll_base + export_table_RVA)
	lea rdx, [rax + rcx]
	; Save it for later
	push rdx
	
	; read function names RVA
	mov ecx, [rdx + 0x20]
	
	; calculate address for function names offsets array (dll_base + function_names_RVA)
	lea rsi, [rax+rcx]

```

## Create a Util to hash functions

```c
// based on xxhash but for one bit
int hash(const char* function_name) {
	int hash = 0;
	unsigned int ch = 0;
	for (; *function_name; function_name++) {
		ch = *function_name;
		// 5 is coprime to 8
		hash += ((ch << 5) | (ch >> (8 - 5)));
	}
	return hash;
}

```
Written a code to travers Kernal32.dll and hash every functions and save it in a file.
## Assembly version for hash function

```asm
_hash:
	xor r9, r9
	xor r8, r8
	_loop:
		mov r8b, [rax]  ; load byte into r8b
		test r8b, r8b   ; check if null terminator?
		jz _done

		rol r8b, 5      ; ((char << 5) | (ch >> (8 - 5)))
		imul r9, r9, 30 ; (r9 * 30)
		add r9, r8      ; r9 + r8
		inc rax         ; increment the pointer to next byte
		jmp _loop
	_done :
		ret
```
### find function by custom hash function

instead of string comparing
1- faster
2- stealthier

`GetProcAdress` hash
![](pics/Pasted%20image%2020260620070345.png)
`LoadLibraryA` hash
![](pics/Pasted%20image%2020260620070402.png)


```
LoadLibraryA -> 0x833f1aa2
GetProcAddress -> 0x76ba08d2
```
## Increment RCX until function is found

```asm
_find_addr :
	; rcx is used as counter
	xor rcx, rcx
	_next:
	inc rcx
	; load function_name offset from [rsi]
	lodsd
	; offset returned in RAX
	; calculate the absulote address baseDll (RDX) + function_name_offset (RAX)
	add rax, rdx
	call _hash
	; compare only the 32 bits of function_hash (R9) vs target_function_hash (R15) (Since there is no collisions)
	cmp r9d, r15d
	jnz _next

	ret
```

## Use the obtained ordinal in addresses of functions array

```asm
_get_address :

	; read function ordinals RVA
	mov esi, DWORD [rdx + 0x24]
	; calculate the address for ordinals offsets array
	lea rdi, [rax + rsi]

	xor rsi, rsi
	; read the ordinal offset 
	mov si, word [rdi + rcx * 2]
	; align (linked-list)
	dec si

	; read the function address offset
	mov ecx, DWORD [rdx + 0x1c]
	; calculate the address for function addresses array
	lea rdi, [rax + rcx]

	; read the target function offset
	mov ecx, DWORD [rdi + rsi * 4]

	; calculate the address of the target function
	lea rdi, [rax + rcx]
	ret
```


## Get Addresses for target functions

Get Address of `GetProcAddress`
Get Address of `LoadLibrary`

without hardcoded addresses everything is dynamically resolved using the PE structure!

```asm
call _get_address
	; save the address of LoadLibA
	push rdi

	mov rcx, r9
	call _get_address

	; save the address of getProcAddress
	push rdi
	call _main
```

## Call the functions

```asm
_main:
	; save getProcAdd
	mov r15, QWORD[rsp+8]

	; used to call loadLibA
	mov rax, QWORD [rsp+16]
	call _load_LibraryA

	; hModule
	mov rcx, rax
	; getProcAddress adress
	mov rax, r15
	call _get_ProcAddress
	; call MessageBoxA
	call _Message_boxA

	ret
```

## Final Result

![](pics/Pasted%20image%2020260619184137.png)

Exit with no Errors
![](pics/Pasted%20image%2020260620072329.png)
## Resources

https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
