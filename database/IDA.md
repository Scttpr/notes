- **URL :** https://hex-rays.com/ida-free/
- **Description :** The free binary code analysis tool to kickstart your reverse engineering experience.
- **Platforms :** [[Windows]], [[Linux]]
- **Category :** [[Tools]]
- **Tags :** [[Malware]], [[Reverse engineering]], [[Binaries]], [[Dissasembler]], [[Debugger]]

## Notes
- `spacebar` - Toggle text view & graph view
- `enter` - Jump to operand
- `esc` - Jump back
- `n` - Rename
- `IDA`'s `Text view` employs arrows to signify different types of control flow instructions and jumps. Here are some commonly seen arrows and their interpretations:
	- `Solid Arrow (→)`: A solid arrow denotes a direct jump or branch instruction, indicating an unconditional shift in the program's flow where execution moves from one location to another. This occurs when a jump or branch instruction like `jmp` or `call` is encountered.
	- `Dashed Arrow (---→)`: A dashed arrow represents a conditional jump or branch instruction, suggesting that the program's flow might change based on a specific condition. The destination of the jump depends on the condition's outcome. For instance, a `jz` (jump if zero) instruction will trigger a jump only if a previous comparison yielded a zero value.