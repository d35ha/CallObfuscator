# CallObfuscator
Obfuscate windows apis from static analysis tools and debuggers
# Theory
This's pretty forward, let's say I've used `VirtualProtect` and I want to obfuscate it with `Sleep`,</br>
the tool will manipulate the IAT so that the thunk that points to `VirtualProtect` will point instead to</br>
`Sleep`,</br>
Now at executing the file, windows loader will load `Sleep` instead of `VirtualProtect`, and moves the execution to the entry point</br>
From there the execution will be redirected to the shellcode , the tool put before, to find the address of</br>
`VirtualProtect` and use it to replace the address of `Sleep` which assigned before by the loader</br>
# How to use
`CallObf.exe [in_file] [out_file] [target_api_0],[new_api_0] [target_api_1],[new_api_1] ...`</br>
# Example
Build this code sample</br>
```c++
#include <windows.h>
#include <stdio.h>

int main() {
	SetLastError(5);
	printf("Last error is %d\n", GetLastError(5));
	return 0;
};
```

After building it, this is how the kernel32 imports look like</br>

![pic1](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic1.PNG)</br>

Now let's obfuscate both `SetLastError` and `GetLastError` with `Beep` and `GetACP` (actually any api from kernel32 will be ok even if it's not imported at all)</br>

![pic2](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic2.PNG)</br>

Again let's have a look on the kernel32 imports</br>

![pic3](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic3.PNG)</br>

There's no existance of `SetLastError` or `GetLastError`</br>
A confirmation that two files will work properly</br>

![pic4](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic4.PNG)</br>

# Impact

IDA HexRays Decompiler</br>

![pic5](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic5.PNG)</br>

IDA Debugger</br>

![pic6](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic6.PNG)</br>

Ghidra</br>

![pic7](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic7.PNG)</br>

ApiMonitor</br>

![pic8](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic8.PNG)</br>

That's because all static analysis tool depend on what is the api name written at IAT which can be manipulated as shown</br>
For ApiMonitor, because of using IAT hooking, the same problem exists</br>

On the other side, for tools like x64dbg the shown api names will only depend on what is actually called (not what written at the IAT)</br>

![pic9](https://github.com/d35ha/CallObfuscator/blob/master/Images/pic9.PNG)</br>

# Additional
* The tool will try to use the code cave for the written shellcode if it's not enough, it will create a new section for it</br>
* It can be used multiple times on the same PE</br>

# Binaries
[CallObf32.exe](https://github.com/d35ha/CallObfuscator/raw/master/Binaries/CallObf32.exe)</br>
[CallObf64.exe](https://github.com/d35ha/CallObfuscator/raw/master/Binaries/CallObf64.exe)</br>
