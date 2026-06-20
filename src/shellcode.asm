; ----------------- Keyword -----------------------------
; modified means the function might change the contents
; unmodified means the function won't change the contents

bits 64

global _start

section .text

_start :

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
	; save for the second call of _find_addr
	push rsi
	; mov dll base to rdx
	mov rdx, rax

	; pass the target hash for (LoadLibrary) (rest is zero'ed out by defualt in x64 assembly)
	mov r15, 0x833f1aa2
	call _find_addr
	
	; retrive 
	pop rsi
	; save LoadLibrary ordinal
	push rcx
	; pass the target hash for (getProcAdress)
	mov r15, 0x76ba08d2
	call _find_addr

	; get address of LoadLibrary first
	; save getProcAdress  ordinal into R9
	pop r9
	xchg r9, rcx
	mov rax, rdx
	; retrieve the export table address
	pop rdx
	; get Address for LoadLibraryA
	call _get_address
	; save the address of LoadLibA
	push rdi

	; retrieve getProcAddress ordinal
	mov rcx, r9
	; get Address for getProcAddress
	call _get_address

	; save the address of getProcAddress
	push rdi
	call _main
	
	; cleanup
	pop r9
	pop r9
	ret

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


; int MessageBox(
;   [in, optional] HWND    hWnd,
;   [in, optional] LPCTSTR lpText,
;   [in, optional] LPCTSTR lpCaption,
;   [in]           UINT    uType
; );

; [in] RAX contain MessageBoxA address
_Message_boxA:
	push rbp
	mov rbp, rsp
	; alloc space for shadow space(32 bytes from rsp down-wards) and strings
	; Keep stack 16 bytes aligned
	sub rsp, 0x50
	
	mov rsi, "Dynamica"
	mov [rsp+0x20], rsi

	mov rsi, "lly Load"
	mov [rsp+0x28], rsi

	mov rsi, " Functio"
	mov [rsp+0x30], rsi

	mov rsi, "ns Via S"
	mov [rsp+0x38], rsi
	
	mov rsi, "hellcode"
	mov [rsp+0x40], rsi

	; micro manage strings (null terminate the caption string and then the title string)
	mov WORD [rsp+0x48], 0x00

	mov rsi, "Titl"
	mov DWORD [rsp+0x4a], esi

	mov BYTE [rsp+0x4e], "e"
	mov BYTE [rsp+0x4f], 0x00
	
	xor rcx, rcx
	lea rdx, [rsp + 0x20]
	lea r8, [rsp + 0x48 + 0x02]
	mov r9, 0x00000002
	call rax

	; cleanup
	mov rsp, rbp
	pop rbp
	ret

; NOT A COMPLETE WRAPPER some parameters are still hardcoded atm...
; [in]  RAX address of getProcAddress
; [in]	RCX hModule
; [out] FARPROC (funcion address)
_get_ProcAddress:
	push rbp
	mov rbp, rsp
	; alloc space for shadow space (32 bytes from rsp down-wards) and strings
	; Keep stack 16 bytes aligned
	sub rsp, 0x40
	
	; construct lpProcName
	mov rsi, "MessageB"
	mov [rsp+0x20], rsi

	mov rsi, "oxA"
	mov [rsp + 0x28], rsi

	; load lpProcName
	lea rdx, [rsp+0x20]

	call rax

	; cleanup
	mov rsp, rbp
	pop rbp
	ret




; NOT A COMPLETE WRAPPER some parameters are still hardcoded atm...
; [Saved] RDX (used for the export table address)
; [Saved] R9 (used for the ordinal)
; [in]  RAX contains LoadLibraryA address
; [out] VOID
_load_LibraryA:
	push r9
	push rdx
	push rbp
	mov rbp, rsp
	sub rsp, 0x30
	mov rcx, "User32.d"
	mov QWORD [rsp+0x28], rcx
	mov rcx, "ll"
	mov QWORD [rsp+0x30] , rcx
	lea rcx, [rsp+0x28]
	call rax
	mov rsp, rbp
	pop rbp
	pop rdx
	pop r9
	ret
; [in] 	RCX ordinal of the function
; [in]  RAX contain dll base
; [in]  RDX contain export table address
; [out] RDI Target function address
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


; [in]  desired hash to find is passed thru r15 (unmodified)
; [in]  RDX contain the dll base address (unmodified)
; [in]  RSI contain the function name offset (modified)
; [out] RCX is the ordinal
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

; [in] expect Address to function name in rax 
; [out] return hash on r9 as 64 bit value
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

; I use it as a signature to tell my Loader my shellcode is finished (to calculate the size dynamically)
nop
nop
nop
