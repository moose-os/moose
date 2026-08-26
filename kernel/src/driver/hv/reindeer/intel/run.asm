// State at entry:
// RCX - mutable reference to space we use to save host registers,
// RDX - mutable reference to space we use to load and save guest registers,
// EDI - boolean indicating if it's first run and we should use VMLAUNCH or VMRESUME

// Save host state
mov [rcx + 0  * 8], rax
mov [rcx + 1  * 8], rbx
mov [rcx + 2  * 8], rcx
mov [rcx + 3  * 8], rdx
mov [rcx + 4  * 8], rbp
mov [rcx + 5  * 8], rsi
mov [rcx + 6  * 8], rdi
mov [rcx + 7  * 8], r8
mov [rcx + 8  * 8], r9
mov [rcx + 9  * 8], r10
mov [rcx + 10 * 8], r11
mov [rcx + 11 * 8], r12
mov [rcx + 12 * 8], r13
mov [rcx + 13 * 8], r14
mov [rcx + 14 * 8], r15
fxsave [rcx + 20 * 8]

// Save host state register
push rcx

// Save guest state register
push rdx

// Save HOST_RSP
mov rax, 0x6c14
vmwrite rax, rsp

// Save HOST_RIP
mov rax, 0x6c16
lea rbx, [rip + 20f]
vmwrite rax, rbx

// Test if we should use VMLAUNCH or VMRESUME
//
// We're doing this now, because we will lose the state after we
// switch GP registers
test edi, edi

// Load guest state
mov rax, [rdx +  0 * 8]
mov rbx, [rdx +  1 * 8]
mov rcx, [rdx +  2 * 8]
mov rbp, [rdx +  4 * 8]
mov rsi, [rdx +  5 * 8]
mov rdi, [rdx +  6 * 8]
mov r8,  [rdx +  7 * 8]
mov r9,  [rdx +  8 * 8]
mov r10, [rdx +  9 * 8]
mov r11, [rdx + 10 * 8]
mov r12, [rdx + 11 * 8]
mov r13, [rdx + 12 * 8]
mov r14, [rdx + 13 * 8]
mov r15, [rdx + 14 * 8]
fxrstor [rdx + 20 * 8]
mov rdx, [rdx +  3 * 8]

jnz 21f

vmresume
jmp 20f

21:
vmlaunch

20:

// Save the VM exit rdx
push rdx

// Restore guest register state pointer
mov rdx, [rsp + 8]

// Save guest state
mov [rdx +  0 * 8], rax
mov [rdx +  1 * 8], rbx
mov [rdx +  2 * 8], rcx
mov [rdx +  4 * 8], rbp
mov [rdx +  5 * 8], rsi
mov [rdx +  6 * 8], rdi
mov [rdx +  7 * 8], r8
mov [rdx +  8 * 8], r9
mov [rdx +  9 * 8], r10
mov [rdx + 10 * 8], r11
mov [rdx + 11 * 8], r12
mov [rdx + 12 * 8], r13
mov [rdx + 13 * 8], r14
mov [rdx + 14 * 8], r15
fxsave [rdx + 20 * 8]

// Get rdx and store it in the guest state
pop rcx
mov [rdx + 3 * 8], rcx

// Pop the guest and host register pointers
pop rdx
pop rcx

// Load the host state
//
// RCX is valid already
mov rax, [rcx +  0 * 8]
mov rbx, [rcx +  1 * 8]
mov rdx, [rcx +  3 * 8]
mov rbp, [rcx +  4 * 8]
mov rsi, [rcx +  5 * 8]
mov rdi, [rcx +  6 * 8]
mov r8,  [rcx +  7 * 8]
mov r9,  [rcx +  8 * 8]
mov r10, [rcx +  9 * 8]
mov r11, [rcx + 10 * 8]
mov r12, [rcx + 11 * 8]
mov r13, [rcx + 12 * 8]
mov r14, [rcx + 13 * 8]
mov r15, [rcx + 14 * 8]
fxrstor [rcx + 20 * 8]

// Now return to the Rust code
