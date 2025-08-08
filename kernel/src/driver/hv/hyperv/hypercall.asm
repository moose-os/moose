section .text
global _do_hypercall
global _do_fast_hypercall
bits 64

; void _do_hypercall(u64 input, u64 input_parameters, u64 output_parameters, u64 hypercall_page)
; Arguments (System V from Rust):
;   rdi = input
;   rsi = input_parameters
;   rdx = output_parameters
;   rcx = hypercall_page
_do_hypercall:

    push rbx     ; Save RBX value

    mov rbx, rcx ; Hypercall Page
    mov r8, rdx  ; Output Parameters GPA - R8 (3rd argument)
    mov rdx, rsi ; Input Parameters GPA - RDX (2nd argument)
    mov rcx, rdi ; Hypercall Input Value - RCX (1st argument)

    ; Perform a call to hypercall page (this effectively calls hypervisor service routine)
    ;
    ; We could use VMCALL/VMMCALL here as well, but Microsoft recommends using Hypercall Page
    call rbx

    pop rbx      ; Restore RBX

    ret ; Return to the Rust code

; u64 _do_fast_hypercall(u64 input, u64 data, u64 hypercall_page)
; Arguments (System V from Rust):
;   rdi = input (HypercallInput)
;   rsi = data (fast hypercall payload)
;   rdx = hypercall_page (GPA)
_do_fast_hypercall:
    push    rbp                ; Save RBP
    mov     rbp, rdx           ; RBP = hypercall_page GPA
    mov     rcx, rdi           ; RCX = input
    mov     rdx, rsi           ; RDX = fast data payload

    call    rbp                ; Execute hypercall

    pop     rbp                ; Restore RBP
    ret
