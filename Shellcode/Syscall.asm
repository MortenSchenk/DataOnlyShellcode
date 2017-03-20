.code

NtUserDefSetText PROC
	mov r10, rcx
	mov eax, 1081h
	syscall
	ret
NtUserDefSetText ENDP

END