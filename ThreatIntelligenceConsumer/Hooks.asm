; /*++
; *
; * @file:      ThreatIntelligenceConsumer/Hooks.asm
; *
; * @summary:   ControlTraceW hook implementation.
; *
; * @author:    Connor McGarr (@33y0re)
; *
; --*/

.CODE

extern k_TraceProperties:QWORD
extern g_OriginalControlTraceW:QWORD

; RCX: TraceId
; RDX: InstanceName
; R8: Properties
; R9: ControlCode
MyControlTraceW PROC
	; If the target operation is anything other than a query,
	; jump to the real ControlTraceW function.
	cmp r9, 0 ; EVENT_TRACE_CONTROL_QUERY
	je hooked_control_tracew
	jmp real_control_tracew

hooked_control_tracew:
	; RDI, RSI, and RCX are going to be used here.
	; Preserve them. Also the flags.
	pushfq
	push rdi
	push rsi
	push rcx

	; R8 is a structure on the stack. Therefore
	; we need to memcpy instead of just assigning
	; the value.
	mov rdi, r8
	mov rsi, k_TraceProperties
	xor rax, rax
	mov eax, 20Fh                    ; Counter: 0x1078 / 8 = 0x20F (527 qwords)

	; memcpy implementation.
memcpy_loop:
    mov rcx, qword ptr [rsi]       ; Read 8 bytes from source
    mov qword ptr [rdi], rcx       ; Write 8 bytes to destination
    add rsi, 8                     ; Advance source
    add rdi, 8                     ; Advance destination
    dec eax                        ; Decrement counter
    jnz memcpy_loop

	; Restore non-volatile registers. And flags.
	pop rcx
	pop rsi
	pop rdi
	popfq

	; bail
	jmp exit_label

exit_label:
	; ERROR_SUCCESS
	xor rax, rax
	ret

; Forward to standalone trampoline that properly executes
; the original ControlTraceW with all parameters intact.
real_control_tracew:
	; Simply jump to the trampoline function in allocated memory.
	; All parameters (RCX, RDX, R8, R9) are still intact.
	; The trampoline will execute the original bytes and return properly.
	int 3
	jmp qword ptr [g_OriginalControlTraceW]
MyControlTraceW ENDP

END