# Duckware Team - Mars Analytic(NorthSec 2018)

###### Solved by @0xpics

> This CTF is about Reverse Engineering

## Sobre o Desafio

Mars Analytica foi um desafio de reverse engineering de alta dificuldade apresentado no NorthSec 2018. O desafio permaneceu não resolvido durante o CTF. O programa se apresenta como um sistema de autenticação que solicita um "Citizen Access ID". O objetivo é descobrir o ID correto que resulta em "ACCESS GRANTED" em vez de "ACCESS DENIED".
## O Desafio


Ao executar o programa temos o seguinte:

[![tarefaaaa.jpg](https://i.postimg.cc/43ChR858/tarefaaaa.jpg)](https://postimg.cc/gxD0vH1R)

Testando o seguinte comando:

```
echo "teste123" | ./tarefa1cp
```

Conseguimos essa respsota:

```
Citizen Access ID:  
[!] ACCESS DENIED - Invalid Citizen ID
[-] Session Terminated
```
Analisando as strings do binário conseguimos o seguinte: 

```
PX!8
&8<3
 oW0 [
td| -
/lib64
nux-x86-
.so.
...
```

Isso mostra que nosso código foi compactado por UPX e precisamos descompactá-lo.

```
upx -d tarefa1cp
```

## Análise

Com o binário descompactado podemos seguir com sua análise no Ghidra.

Dentro do descompilador descombrimos sua main:

```
void FUN_00400da9(void) {
  time_t tVar1;
  undefined1 auStack_2d088 [9536];    // Array 1
  undefined1 auStack_2ab48 [9536];    // Array 2  
  undefined1 auStack_28608 [11104];   // Array 3
  undefined1 auStack_25aa8 [11104];   // Array 4
  undefined1 auStack_22f48 [143160];  // Array 5
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);  // Seed com tempo atual
  
  // Copia 5 arrays grandes para a stack
  memcpy(auStack_2d088, &DAT_00e4dc00, 0x253c);   // 9536 bytes
  memcpy(auStack_2ab48, &DAT_00e50140, 0x253c);   // 9536 bytes
  memcpy(auStack_28608, &DAT_00e52680, 0x2b5c);   // 11104 bytes
  memcpy(auStack_25aa8, &DAT_00e551e0, 0x2b5c);   // 11104 bytes
  memcpy(auStack_22f48, &PTR_LAB_00e57d40, 0x56b8); // 143160 bytes
  
  return;
}
```
Esta função é o inicializador da Máquina Virtual (VM) do desafio. Ela prepara todo o ambiente para a VM funcionar.

O código se divide em duas principais partes:

1. Criação de Stack:

```
undefined1 auStack_2d088 [9536];    // Array 1
undefined1 auStack_2ab48 [9536];    // Array 2  
undefined1 auStack_28608 [11104];   // Array 3
undefined1 auStack_25aa8 [11104];   // Array 4
undefined1 auStack_22f48 [143160];  // Array 5
```

2. Copia 5 Arrays para a Stack

```
memcpy(auStack_2d088, &DAT_00e4dc00, 0x253c);   // Copia Array 1
memcpy(auStack_2ab48, &DAT_00e50140, 0x253c);   // Copia Array 2
memcpy(auStack_28608, &DAT_00e52680, 0x2b5c);   // Copia Array 3  
memcpy(auStack_25aa8, &DAT_00e551e0, 0x2b5c);   // Copia Array 4
memcpy(auStack_22f48, &PTR_LAB_00e57d40, 0x56b8); // Copia Array 5
```

Estes arrays são a "programação" da VM. Eles definem:

* Qual handler executar a cada passo

* A ordem em que os handlers rodam

* Toda a lógica do programa

Para acharmos o ID então precisaremos extrair a lógica dos arrays que descobrimos como verficar o ID, e então usamos um solver para calcular qual ID satisfaz essa lógica.

## Resolvendo o Desafio

Para extrairmos a lógica usaremos o seguinte código:

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryAccessException

TAB1_BASE = 0x00e4dc00
TAB2_BASE = 0x00e50140  
TAB3_BASE = 0x00e52680
TAB4_BASE = 0x00e551e0
TAB5_BASE = 0x00e57d40

# Array sizes (from memcpy)
TAB1_SIZE = 0x253c
TAB2_SIZE = 0x253c
TAB3_SIZE = 0x2b5c  
TAB4_SIZE = 0x2b5c
TAB5_SIZE = 0x56b8

def read_dword(address):
    """Read 4 bytes from address as DWORD"""
    try:
        addr = toAddr(address)
        memory = getBytes(addr, 4)
        if memory and len(memory) == 4:
            return int.from_bytes(memory, byteorder='little', signed=False)
    except:
        pass
    return 0

def read_qword(address):
    """Read 8 bytes from address as QWORD"""  
    try:
        addr = toAddr(address)
        memory = getBytes(addr, 8)
        if memory and len(memory) == 8:
            return int.from_bytes(memory, byteorder='little', signed=False)
    except:
        pass
    return 0

# Load arrays
print("Loading VM arrays...")
tab1 = [read_dword(TAB1_BASE + i) for i in range(0, TAB1_SIZE, 4)]
tab2 = [read_dword(TAB2_BASE + i) for i in range(0, TAB2_SIZE, 4)]
tab3 = [read_dword(TAB3_BASE + i) for i in range(0, TAB3_SIZE, 4)]
tab4 = [read_dword(TAB4_BASE + i) for i in range(0, TAB4_SIZE, 4)]
tab5 = [read_qword(TAB5_BASE + i) for i in range(0, TAB5_SIZE, 8)]

print("Arrays loaded!")
print("tab1: {} values".format(len(tab1)))
print("tab2: {} values".format(len(tab2))) 
print("tab3: {} values".format(len(tab3)))
print("tab4: {} values".format(len(tab4)))
print("tab5: {} values".format(len(tab5)))

def dispatcher(num):
    """Calculate next handler based on PC"""
    global tab1, tab2, tab3, tab4, tab5
    
    try:
        # Complex dispatcher calculation - SAME LOGIC AS WRITE-UP
        idx1 = (num * 1962) % len(tab1)
        val1 = tab1[idx1]
        
        idx2 = (val1 * 1445) % len(tab2) 
        val2 = tab2[idx2]
        
        idx3 = (val2 * 601) % len(tab3)
        val3 = tab3[idx3]
        
        idx4 = (val3 * 469) % len(tab4)
        eax = tab4[idx4]
        
        edx = tab5[idx2]  # Use idx2 from previous calculation
        
        return eax + edx
    except:
        return 0

def get_imm(num):
    """Get immediate value for current PC"""
    global tab1, tab2, tab5
    
    try:
        idx1 = (num * 1962) % len(tab1)
        val1 = tab1[idx1]
        
        idx2 = (val1 * 1445) % len(tab2)
        
        # +1 index for tab5 (as in original code)
        imm_idx = idx2 + 1
        if imm_idx < len(tab5):
            return tab5[imm_idx]
    except:
        pass
    return 0

def disassemble_vm():
    """Disassemble VM and extract STORE order"""
    pc = 0
    stores_found = []
    loads_found = []
    
    print("\nStarting VM disassembly...")
    print("PC\tHandler\t\tInstruction")
    print("-" * 60)
    
    # Analyze first 2000 handlers (adjust if needed)
    for _ in range(2000):
        handler = dispatcher(pc)
        
        # Identify instruction type based on handler address
        if handler == 0x402335:  # PUSH immediate
            imm = get_imm(pc)
            print("0x{:04x}\t0x{:08x}\tpush 0x{:08x}".format(pc, handler, imm))
            
        elif handler == 0x401b8f:  # STORE [index]
            imm = get_imm(pc)
            stores_found.append(imm)
            print("0x{:04x}\t0x{:08x}\tstore[0x{:08x}] <--- STORE FOUND".format(pc, handler, imm))
            
        elif handler == 0x401f62:  # LOAD [index] 
            imm = get_imm(pc)
            loads_found.append(imm)
            print("0x{:04x}\t0x{:08x}\tload[0x{:08x}]".format(pc, handler, imm))
            
        elif handler == 0x40346D:  # BREAK (from write-up)
            print("0x{:04x}\t0x{:08x}\tbreak".format(pc, handler))
            break
            
        elif handler == 0x4018cd:  # NOP (from write-up)
            print("0x{:04x}\t0x{:08x}\tnop".format(pc, handler))
            
        elif handler == 0x402ab2:  # SWAP (from write-up)
            print("0x{:04x}\t0x{:08x}\tswap".format(pc, handler))
            
        else:
            # Unknown handler - show hex for debug
            print("0x{:04x}\t0x{:08x}\tunknown".format(pc, handler))
        
        pc += 1
        
        # Stop if found many stores (optimization)
        if len(stores_found) >= 19:  # We expect 19 stores
            print("Found {} stores - possibly complete order".format(len(stores_found)))
            break
    
    return stores_found, loads_found

# Execute disassembly
print("=== MARS ANALYTICA VM DISASSEMBLY ===")
print("Based on scud's write-up (NSEC 2018)")
stores, loads = disassemble_vm()

print("\n=== RESULTS ===")
print("Stores found (hex):", [hex(x) for x in stores])
print("Stores found (decimal):", stores)
print("Total stores:", len(stores))

print("\nLoads found (hex):", [hex(x) for x in loads[:10]], "...")  # First 10

if stores:
    print("\n*** REARRANGEMENT ORDER FOUND! ***")
    print("Use this order in Z3 solver:", stores)
    
    # Check if matches write-up
    expected = [7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]
    if stores == expected:
        print("\n*** PERFECT! Order IDENTICAL to write-up! ***")
    else:
        print("\n*** WARNING: Different order from write-up. Use the one above. ***")
else:
    print("\n*** No stores found. Checking problems... ***")
    # Debug: test dispatcher for some values
    print("\nDispatcher test (PC 0-5):")
    for i in range(6):
        h = dispatcher(i)
        print("PC {} -> Handler: 0x{:08x}".format(i, h))
```

Este código, feito para rodar no PyGhidra, desmonta a Máquina Virtual para descobrir como o programa verifica o Citizen ID.

Rodando o código conseguimos a lógica abaixo(versão resumida só para exemplificar pois é a lógica completa é muito grande):

```
...
0x6f2: 0x401f62: load[0x00000009]    ⬅️ Pega o caractere da POSIÇÃO 9
0x6f3: 0x401f62: load[0x0000001b]    ⬅️ Pega o caractere da POSIÇÃO 27 (0x1b = 27)
0x6f4: 0xbde28a: mul                  ⬅️ MULTIPLICA: flag[9] * flag[27]
0x6f5: 0x401f62: load[0x00000017]    ⬅️ Pega o caractere da POSIÇÃO 23 (0x17 = 23)  
0x6f6: 0x401f62: load[0x00000012]    ⬅️ Pega o caractere da POSIÇÃO 18 (0x12 = 18)
0x6f7: 0x402ab2: swap                 ⬅️ Troca ordem na stack
0x6f8: 0xbdf48d: sub                  ⬅️ SUBTRAI: flag[23] - flag[18]
0x6f9: 0x401f62: load[0x0000001d]    ⬅️ Pega o caractere da POSIÇÃO 29 (0x1d = 29)
0x6fa: 0x402ab2: swap                 ⬅️ Troca ordem
0x6fb: 0xbe059f: xor                  ⬅️ XOR: (flag[23]-flag[18]) ^ flag[29]
0x6fc: 0xbe1957: mul                  ⬅️ MULTIPLICA os dois resultados: (flag[9]*flag[27]) * ((flag[23]-flag[18])^flag[29])
0x6fd: 0x402335: push 0x00003fcf      ⬅️ Coloca o valor 0x3fcf (16335) na stack
0x6fe: 0xbe2b48: cmp                  ⬅️ COMPARA: resultado deve ser IGUAL a 0x3fcf
...
```

Quando analisamos o assembly da Máquina Virtual, conseguimos observar um padrão muito interessante. A VM não verifica o ID de forma simples, mas sim através de uma série de operações matemáticas complexas entre diferentes posições dos caracteres digitados.

Cada bloco de instruções que vimos - com múltiplos `load` seguidos de operações como `mul`, `sub`, `xor`, e terminando com `push` de um valor e `cmp` - representa na verdade uma equação matemática que o ID válido deve satisfazer.

Este código é uma função simples que tem como objetivo criar uma string HTML contendo um elemento de input.

Mas descobrir as equações sozinho não basta - precisamos também entender como os caracteres são organizados na memória da VM. É aí que entra a ordem de rearranjo que encontramos com o desmontador. Ele nos mostrou que quando digitamos um ID, os caracteres não ficam em posições sequenciais, mas são espalhados seguindo uma ordem específica: `[7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]`.

Combinando essas duas peças do quebra-cabeça - a ordem dos caracteres e as equações de verificação - podemos então construir um solver que encontra automaticamente a solução. O Z3 Theorem Prover é perfeito para isso, pois ele é especializado em resolver sistemas complexos de equações com restrições.

Usaremos o seguinte código:

```
from z3 import *

solver = Solver()

order = [7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]
flag = {}
for i in order:
    flag[i] = BitVec("c_%d" % i, 8)

for k in flag.keys():
    solver.add(flag[k] >= 32, flag[k] <= 126)

solver.add((flag[9] * flag[27]) * ((flag[23] - flag[18]) ^ flag[29]) == 0x3fcf)
solver.add((flag[17] ^ flag[8]) ^ (flag[1] - flag[22]) == 0x53)
solver.add((flag[30] - flag[25]) * ((flag[26] + flag[4]) ^ flag[7]) == 0xffffe8f2)
solver.add(flag[15] - flag[28] == 0xb)
solver.add((flag[16] + flag[13]) ^ flag[21] == 3)
solver.add((flag[1] - flag[16]) + flag[21] == 0xb0)
solver.add(((flag[4] ^ flag[18]) - (flag[17] + flag[28])) ^ flag[27] == 0xffffff39)
solver.add((flag[25] * flag[13]) + ((flag[7] ^ flag[30]) * flag[8]) == 0x2701)
solver.add((flag[29] * flag[9]) - flag[22] == 0x823)
solver.add((flag[15] + flag[23]) - flag[26] == 0x6e)
solver.add((flag[29] + flag[4]) + (flag[18] * flag[21]) == 0x15fe)
solver.add((flag[26] - flag[25]) - (flag[7] + flag[13]) == 0xffffff4a)
solver.add((flag[9] ^ flag[22]) * flag[30] == 0x1c20)
solver.add((flag[28] * flag[27]) + (flag[15] * flag[8]) == 0x45d0)
solver.add((flag[23] - flag[1]) - (flag[16] * flag[17]) == 0xffffeae0)
solver.add((flag[1] * flag[15]) + (flag[13] * flag[28]) == 0x49c8)
solver.add((flag[29] + flag[26]) * flag[25] == 0x3ac9)
solver.add((flag[18] + flag[7]) * flag[30] == 0x2f76)
solver.add((flag[9] ^ flag[27]) * flag[17] == 0x2760)
solver.add((flag[23] + flag[22]) - flag[16] == 0x84)
solver.add((flag[4] * flag[8]) + flag[21] == 0x995)

if solver.check() == sat:
    model = solver.model()
    solution = ''.join(chr(model[flag[i]].as_long()) for i in order)
    print("SOLUÇÃO ENCONTRADA:", solution)
```

O código cria um solver Z3 e define a ordem de rearranjo que descobrimos. Para cada posição, criamos uma variável simbólica representando um caractere, com a restrição de que deve ser ASCII imprimível (entre 32 e 126), já que um ID válido usa letras, números e símbolos.

As 19 equações adicionadas ao solver são exatamente as mesmas que a VM verifica. Cada `solver.add()` representa uma condição obrigatória para o ID ser aceito. O Z3 age como um detetive matemático, testando combinações até encontrar uma que satisfaça todas as equações ao mesmo tempo.

Quando encontra uma solução (`sat` significa "satisfazível"), o solver constrói a string na ordem correta, resultando no Citizen Access ID que passará em todas as verificações da VM. A vantagem é que não precisamos adivinhar - o Z3 resolve o sistema de equações inteligentemente e nos dá a resposta exata.

## A solução

Executando o código conseguimos a seguinte string: 

`q4Eo-eyMq-1dd0-leKx`

Inserindo o ID encontrado conseguimos a flag:

`q4Eo-eyMq-1dd0-leKx`

## Conclusão

O desafio Mars Analytica mostrou que mesmo proteções complexas como máquinas virtuais customizadas podem ser revertidas com análise cuidadosa. Ao entender como a VM funcionava e extrair as regras matemáticas que ela usava para verificar o ID, conseguimos usar ferramentas como o Z3 para resolver o problema de forma eficiente. A solução demonstra que, com as técnicas certas, é possível desvendar até os desafios de engenharia reversa mais bem elaborados.
