- **URL :** https://rada.re/n/, https://github.com/radareorg/radare2
- **Description :** Libre and Portable Reverse Engineering Framework
- **Platforms :** [[C]]
- **Category :** [[Tools]]
- **Tags :** [[Dissasembler]], [[Debugger]], [[Reverse engineering]], [[Framework]]

## Cheatsheet

- `<command>?` - display help
- `<command>~<str>` - grep
- `<command> @` - temporary seek to this address
- `<command> @@` - foreach iterator command

#### Normal mode

| command | description |
| --- | --- |
| `afl` | list functions |
| `iz` | strings in data section |
| `iz` | strings in whole binary |
| `pdf` | disassemble function |
| `pd` | disassemble N instructions |
| `axt` | find data/code references to this address |
| `V` | visual mode |
| `V!` | visual mode enhanced |
| `VV` | graph mode |

__Exemples :__

- `pd 1@<addr>` - dissasemble 1 instruction at `addr`
- `axt` - check cross references on current pointer
#### Visual mode

| command | description |
| --- | --- |
| `p` | navigate view forward |
| `P` | navigate view backward |
| `enter` | go to function |
| `u` | go back |
| `space` | switch visual & graph |
| `q` | return to normal mode |
| `:` | command |
