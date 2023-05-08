.CODE



get_ret_address PROC

pop rax
push rax
ret
get_ret_address ENDP


HashString PROC

 push rsi
 push rdi
 mov rsi,rcx
 calc_hash:
 xor rdi,rdi
 cld
 hash_iter :
 xor rax,rax
 lodsb
 cmp al,ah
 je hash_done
 ror edi,0Dh
 add edi,eax
 jmp hash_iter
 hash_done:
 mov rax,rdi
 pop rdi
 pop rsi
 ret

HashString ENDP


findkernel32 PROC

xor rax,rax
mov rax,gs:[60h]
mov rax,[rax+18h]
mov rax,[rax+20h]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax+20h]
ret 

findkernel32 ENDP


findkernelbase PROC

xor rax,rax
mov rax,gs:[60h]
mov rax,[rax+18h]
mov rax,[rax+20h]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax+20h]
ret 

findkernelbase ENDP



END