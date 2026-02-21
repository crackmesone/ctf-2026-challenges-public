# solution is 1012321103210033011233322110103321001
.intel_syntax noprefix
.global _start
.text

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [enter_pwd]
    mov rdx, 0xf
    syscall

get_pwd:
    xor rax, rax
    xor rdi, rdi
    lea rsi, [buffer]
    mov rdx, 0x26
    syscall

verify_pwd:
    lea rbx, [buffer]
    mov rcx, 0x26
next_char:
    dec rcx
    js pwd_ok
    movzx rax, BYTE PTR [rbx + rcx]
	mov rdx, 0xf000000000400
	bt rdx, rax
	jnc bad_job
    jmp next_char

pwd_ok:
    mov rax, 0xb6fd071e9c8a3425
    xor rdi, rdi

next_move:
    # rax is state
    # rbx is input
    # rcx is -1
    # rdx empty
    # rdi is char_idx
    mov rsi, 0x2000000000
    bt rsi, rdi
    jc check
    mov dl, [rbx + rdi]
    inc rcx # rcx is now 0

find_zero:
    shl rcx, 2
    ror rax, cl
    mov rsi, rax
    and sil, 0x0F        

loop_xor:
    push rsi
    neg BYTE PTR [rsp] 
    or sil, BYTE PTR [rsp]
    jz found_zero
    rol rax, cl
    shr rcx, 2
    inc rcx
    jmp find_zero

found_zero:
    # at this point
    # rax = current_state
    # rbx = input
    # rcx = offset_0
    # dl = move
    # rdi = ptr_current_move
    rol rax, cl
    shr rcx, 2
    movzx rdx, dl
    add rsp, 8
    mov rsi, 0x3BB97FFD7FFD6EEC 
    shl rcx, 2
    add dl, 0xd0
    add rcx, rdx
    bt rsi, rcx
    jnc bad_job

    sub rcx, rdx
    
    lea rdx, [2 * rdx + 6]
    call $+5
    pop rsi
    add rsi, rdx
    jmp rsi

    jmp j_0
    jmp j_1
    jmp j_2
    jmp j_3

j_0:
    push 0xf0
    jmp do_move
j_1:
    push 0xfc
    jmp do_move
j_2:
    push 0x10
    jmp do_move
j_3:
    push 0x4

do_move:
   push rax
   add cl, [rsp + 0x8]
   ror QWORD PTR [rsp], cl
   movzx rsi, BYTE PTR [rsp]
   and BYTE PTR [rsp], 0xf0
   and rsi, 0x0f
   neg rcx
   add rcx, 64
   ror QWORD PTR [rsp], cl
   sub rcx, 64
   neg rcx
   sub cl, [rsp + 0x8]
   ror QWORD PTR [rsp], cl
   or BYTE PTR [rsp], sil
   neg rcx
   add rcx, 64
   ror QWORD PTR [rsp], cl
   pop rax
   add rsp, 8
   inc rdi
   xor rcx, rcx
   not rcx
   jmp next_move

check:
    mov rbx, 0x0123456789ABCDEF
    xor rax, rbx
    mov rbx, 0x1111111111111111
    xor rax, rbx
    mov rbx, 0xeeeeeeeeeeeeeeee
    xor rax, rbx
    test rax, rax
    jnz bad_job

good_job:
    mov rax, 1
    mov rdi, 1
    lea rsi, [good_job_message]
    mov rdx, 40
    syscall
    jmp end
bad_job:
    mov rax, 1
    mov rdi, 1
    lea rsi, [bad_job_message]
    mov rdx, 0xf
    syscall
end:
    mov rax, 60
    syscall

enter_pwd:
.asciz "enter password\n"
good_job_message:
.asciz "good job, validate with CMO{your_input}\n"
bad_job_message: 
.asciz "wrong password\n"
buffer: 
.fill 38, 1, 0
