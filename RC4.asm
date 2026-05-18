assume cs:code, ds:data, es:data

data segment
key_len db 1 dup(0)
key db 256 dup(0)
text_len db 1 dup(0)
plaintext db 256 dup(0)
ciphertext db 256 dup(0)

s db 256 dup(0)
k db 256 dup(0)
temp db 1 dup(0) ; 用于交换
buf db 255,'?',256 dup(0) ;8086最多支持一次读取255个字符

;msg0 db "enter your key's length: (length must be the same as your text)",'$'
msg1 db "enter your key(usually 128 bit):",'$' ;0ah是换行符，0dh是回车符（光标回到这一行开头）
msg4 db 0ah,"enter '0' for crypt or '1' for decrypt:",'$'
msg5 db 0ah,"error!Please enter '0' for crypt or '1' for decrypt:",'$'
msg6 db 0ah,"enter '0' for string input or '1' for hex input:",'$'
msg7 db 0ah,"error!Please enter '0' for string or '1' for hex.",'$'
msg2 db 0ah,"enter the plaintext(less than 256 bit):",'$'
msg3 db 0ah,"enter the ciphertext(better more than 4bit and must be less than 256 bit):",'$'
msg8 db 0ah,"error!Hex input cannot include invalid char.",'$'



data ends


code segment
start:
mov ax, data;段初始化
mov ds, ax
mov es,ax

call input

call initial

call encipher

call output

;dontstop:
;jmp dontstop

mov ah, 4ch
int 21h
                                                    





initial proc near
;/*初始化函数*/
;void rc4_init(unsigned char*s,unsigned char*key, unsigned long len)
;{
;    int i=0,j=0;
;    unsigned char k[256]={0};
;    unsigned char tmp=0;
;    for(i=0;i<256;i++) {
;        s[i]=i;
;        k[i]=key[i%len];
;    }
;    for(i=0;i<256;i++) {
;        j=(j+s[i]+k[i])%256;
;        tmp=s[i];
;        s[i]=s[j];//交换s[i]和s[j]
;        s[j]=tmp;
;    }
;}
;---------------------------------------------------------------------------------------------------------

mov bx, 0;i
mov dl, key_len
next1: ;按规则设置好准备交换打乱
mov al, bl
mov ah, 0
mov s[bx], al;s初始化
div dl ;ah放余数，al放商
mov al, ah
mov ah, 0
mov si, ax ;s[i]=i
mov dh, key[si] 
mov k[bx], dh;k初始化
inc bx
cmp bx, 256
jb next1 ;相当于for循环

mov bx, 0;i
mov ax, 0;j
next2: ;打乱
mov dh, 0
mov dl, s[bx]
add ax, dx
mov dl, k[bx] 
add ax, dx
mov dx, 0 ;j+s[i]+k[i]
mov si, 256
div si ;计算j
mov si, dx
mov ax, dx
mov dl, s[bx] ;交换s[i]和s[j]
mov temp, dl
mov dl, s[si]
mov s[bx], dl
mov dl, temp
mov s[si], dl
inc bx
cmp bx, 256
jb next2

ret
    
initial endp

;------------------------------------------------------------------------------------------------------------

encipher proc near
;/*加解密*/
;void rc4_crypt(unsigned char*s,unsigned char*data,unsigned long len)
;{
;    int i=0,j=0,t=0;
;    unsigned long k=0;
;    unsigned char tmp;
;    for(k=0;k<len;k++)
;    {
;        i=(i+1)%256;
;        j=(j+s[i])%256;
;        tmp=s[i];
;        s[i]=s[j];//交换s[x]和s[y]
;        s[j]=tmp;
;        t=(s[i]+s[j])%256;
;        data[k]^=s[t];
;    }
;}RC4是对称加密，所以加解密都用这个函数

mov bx, 0;k
mov si, 0;i
mov di, 0;j
mov cx, 256

next3:
mov ax, si
inc ax
mov dx, 0
div cx 
mov si, dx ;i=(i+1)%256
mov al, s[si]
mov ah, 0
add di, ax
mov ax, di
mov dx, 0
div cx
mov di, dx ;j=(j+s[i])%256;
mov al, s[si]
mov temp, al
mov al, s[di]
mov s[si], al
mov al, temp
mov s[di], al
mov al, s[si]
add al, s[di] ;t=(s[i]+s[j])%256
jnc next4 ;没有进位则ah=0，有进位则ah=1，因为s[i]+s[j]可能大于256
mov ah, 1
jmp next5
next4:
mov ah, 0
next5:
mov dx, 0
div cx
push si
mov si, dx ;改s的下标为t，除出来的余数在dx
mov al, s[si]
mov ah, plaintext[bx]
xor ah, al
mov ciphertext[bx], ah
pop si
inc bx
cmp bl, text_len
jb next3
mov ciphertext[bx],'$'
ret    
    
encipher endp

;---------------------------------------------------------------------------------------------------------------

input proc near


mov dx, offset msg1
mov ah, 09h
int 21h

mov bx, 0
mov dx,offset buf
mov ah,0Ah
int 21h ;利用int 21h的10号子程序带回显地读取键盘输入
mov cl,buf[1] ;获取字符串长度
mov ch,0
mov key_len,cl 
mov si,offset buf+2 ;输入的第一个字节是输入的最大长度，第二个字节是实际输入的字符数
mov di,offset key
cld
rep movsb ;复制字符串到key



mov dx, offset msg4
mov ah, 09h
int 21h

next8:
mov ah, 01h       
int 21h ;读取用户选择加密或是解密
cmp al, 30h
je next6
cmp al, 31h
je next7
mov dx, offset msg5
mov ah, 09h
int 21h
jmp next8

next6: ;提示输入明文进行加密
mov dx, offset msg2
mov ah, 09h
int 21h
jmp next9

next7: ;解密
mov dx,offset msg6;询问输入的是字符串还是十六进制
mov ah,09h
int 21h

;读取用户选择
mov ah,01h
int 21h
cmp al,30h
je input_string
cmp al,31h
je input_hex
mov dx,offset msg7;无效选择，重新提示
mov ah,09h
int 21h
jmp next7

input_string: ;提示输入密文进行解密
mov dx, offset msg3
mov ah, 09h
int 21h
jmp next9

input_hex: ;提示输入密文进行解密
mov dx, offset msg3
mov ah, 09h
int 21h
mov dx, offset buf
mov ah, 0Ah
int 21h
call hex_to_string ; 将十六进制转为字符串存储到 plaintext
ret

invalid_input:
mov dx, offset msg8
mov ah, 09h
int 21h
jmp input_hex


next9: ;加密
mov dx,offset buf
mov ah,0Ah
int 21h 
mov cl,buf[1] ;获取字符串长度
mov ch,0
mov text_len,cl 
mov si,offset buf+2 
mov di,offset plaintext
cld
rep movsb ;复制字符串到plaintext

ret


hex_to_string:
    mov si, offset buf + 2 ; 输入字符串起始位置（跳过前面的长度字节）
    mov di, offset plaintext ; 输出字符串起始位置

    mov ch, buf[1]       
    shr ch, 1            
    mov text_len, ch     ; 将结果存储到 text_len
    
    shl ch, 1            
    cmp ch, buf[1]       ; 检查是否有变化
    je no_adjustment     ; 如果相等，说明原来是偶数，不需要调整
    
    jc invalid_input      ; 如果不相等，说明原来是奇数，输入异常（两位十六进制字符代表一个ASCII码）

no_adjustment:

    mov ah,0 ; 用于保存转换后的字节值
convert_loop:
    ; 检查是否处理完所有输入字符
    cmp ch, 0
    je convert_done

    ; 读取第一个十六进制字符
	cld
    lodsb
    call hex_char_to_bin
	jc invalid_input
	mov ah,al
	mov cl,4
    shl ah,cl ; 将第一个十六进制字符转为二进制后再乘16就是一个字节的高四位

    ; 读取第二个十六进制字符
	cld
    lodsb
    call hex_char_to_bin
	jc invalid_input
    or ah, al ; 将低四位合并到字节的低四位

    ; 保存结果字节到输出缓冲区
	mov al,ah
	cld
    stosb

    ; 减少处理的字符数
    sub ch, 2 ;两位十六进制字符才代表一位
    jmp convert_loop

convert_done:
    ret

; 将单个十六进制字符转换为二进制值
; 输入: AL = 十六进制字符 ('0'-'9', 'A'-'F', 'a'-'f')
; 输出: AL = 二进制值 (0-15)
hex_char_to_bin:
    cmp al, '0'
    jb invalid_hex_char
    cmp al, '9'
    jna is_digit
    cmp al, 'A'
    jb invalid_hex_char
    cmp al, 'F'
    jna is_uppercase_hex
    cmp al, 'a'
    jb invalid_hex_char
    cmp al, 'f'
    jna is_lowercase_hex
    jmp invalid_hex_char

is_digit:
    sub al, '0'
	clc
    ret

is_uppercase_hex:
    sub al, 'A' - 10
	clc
    ret

is_lowercase_hex:
    sub al, 'a' - 10
	clc
    ret

invalid_hex_char:
    stc
	ret

input endp

;---------------------------------------------------------------------------------------------------------

output proc near

mov dl, 0ah
mov ah, 02h
int 21h
; 输出 ciphertext 字符串
mov dx, offset ciphertext
mov ah, 09h
int 21h


mov dl, 0ah
mov ah, 02h
int 21h

; 初始化寄存器
mov si, offset ciphertext  ; SI 指向 ciphertext 字符串

; 循环遍历字符串
print_hex:
    mov al, [si]           ; 取当前字符
    cmp al, '$'            ; 判断是否为字符串结束符
    je end_print_hex       ; 若是，跳转到结束标签

    call print_char_hex    ; 调用打印字符的十六进制表示的过程

    inc si                 ; 指向下一个字符
    jmp print_hex          ; 重复循环

end_print_hex:
ret

output endp

; 打印 AL 寄存器中字符的十六进制表示
print_char_hex proc near
    push ax                ; 保存 AX 寄存器
	push bx
	
    mov bl, al             ; 保存字符
	mov cl,4
    shr al, cl              ; 高四位
    call print_nibble      ; 打印高四位

    mov al, bl             ; 恢复字符
    and al, 0Fh            ; 低四位
    call print_nibble      ; 打印低四位

    ; 输出 'h'
    mov dl, 'h'
    mov ah, 02h
    int 21h

    ; 输出空格
    mov dl, ' '
    mov ah, 02h
    int 21h

	pop bx
    pop ax                 ; 恢复 AX 寄存器
    ret
print_char_hex endp

; 打印 AL 寄存器中的单个 4 位数 (nibble) 的十六进制表示
print_nibble proc near
    add al, '0'            ; 转换成字符
    cmp al, '9'
    jna short print_digit  ; 如果小于等于 '9'，直接打印

    add al, 7              ; 否则加上 7 以转换成 A-F

print_digit:
    mov dl, al
    mov ah, 02h
    int 21h
    ret
print_nibble endp




code ends
end start
