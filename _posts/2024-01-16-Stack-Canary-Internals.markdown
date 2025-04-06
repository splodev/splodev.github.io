---
layout: post
title:  "Всё что вы хотели и не хотели знать о стековой канарейке"
date:   2025-04-07 13:37:00 +0300
categories: internals mitigations
tags: linux userspace stack_canary
---

![](/assets/Stack-Canary-Internals/logo.jpg)

*Больше райтапов и материалов по пывну в [телеграм канале](https://t.me/sploitdev)*

## Введение

Стековая канарейка или стековая куки. Вы можете встретить это определение во многих статьях и курсах. Англоязычный термин stack canary, stack cookie или stack protector используется для обозначения технологии, позволяющей защитить стек от переполнения буфера.

Чаще всего обучающие материалы по бинарной эксплуатации начинаются с подробного разбора устройства стека и уязвимости переполнения буфера на стеке. Но о стековой канарейке пишут не так часто. Хотя понимание устройства защиты позволяет лучше понять как ее обойти. 

В этом материале мы подробно разберем устройство стековой канарейки. А если вы хотите освежить в памяти тему переполнения буфера на стеке, советуем почитать ресурсы, о которых мы писали в предыдущих статьях.

В качестве примера мы возьмём 4 варианта реализации канарейки: user space Windows/Linux, kernel space Windows/Linux.
## Базовый принцип работы

Стековая канарейка — это случайные байты на стеке перед указателем на фрейм предыдущей функции и адресом возврата. Она защищает их от перезаписи. Например, когда есть уязвимость переполнения буфера на стеке.

Идея защиты в том, что в конце работы функции перед восстановлением стека и возврата на адрес вызывающей функции происходит проверка. Так можно понять был ли повреждён стек и задеты два указателя после канарейки. Изменение даже 1 бита канарейки приведёт к аварийному завершению программы.

Использование стека может отличаться в зависимости от архитектуры. Мы будем опираться на х86-64. 
## Реализация

**Платформа**: Linux
**Контекст**: user space
**Компилятор**: gcc
**Библиотека**: glibc

TL;DR
1. Канарейка добавляется компилятором;
2. В каждой функции в прологе берём значение из fs:0x28, кладём на стек перед указателем на стековый фрейм прошлой функции и адресом возврата;
3. Перед возвратом из функции проверяем значение;
4. В fs:0x28 значение кладёт загрузчик;
5. В загрузчике значение появляется из системного загрузчика исполняемых файлов в ядре.

А теперь подробнее.

Рассмотрим типичный стек с канарейкой для программы пользовательского режима под Linux, собранной через gcc.

Код выглядит так:
```c
#include <stdio.h>

int main() {
    char buf[100];
    gets(buf);
    return 0;
}
```

Для сборки используется стандартная команда:
```sh
gcc ex1.c -o ex1
```

<details>
<summary>Заметки на полях</summary>
*При компиляции вы увидите сообщение с предупреждением о том, что использование функции `gets` небезопасно. Она не проверяет размер считываемых данных, поэтому получается уязвимость переполнения буфера на стеке. В нашей программе есть эта уязвимость, но стековая канарейка мешает ее проэксплуатировать.*
</details>

Запускаем полученный исполняемый файл под отладчиком и смотрим на начало функции:
```sh
gdb ./ex1
gef➤  start
```

Запускаем отладчик и смотрим в начало функции `main` . В прологе записывается канарейка:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241224232403.png)

На скрине можно увидеть стек и код. Текущий адрес выполнения на момент остановки программы подсвечен зелёным цветом и такой же стрелкой указывающей на адрес строчки кода.

Нас интересует две следующие инструкции. Они кладут 8-байтное значение из регистра `fs` по смещению 0x28 на стек. Это канарейка. 

Посмотрим какое именно значение и куда будет положено:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241225002537.png)

На скрине регистр `rax` равен `0x691605e5eced100` — это значение канарейки. Оно будет записано по адресу в регистре `rbp-0x8`, он равен `0x7fffffffd988`. 

Теперь посмотрим, где проходит проверка:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241225003036.png)

Перед выходом из функции достаём со стека значение канарейки и сравниваем с находящейся по адресу `fs:0x28`. 
Если сравнение успешно, переходим на инструкцию `leave` и следующую за ней `ret`. 
Если нет, то попадаем на вызов функции `__stack_chk_fail`. Тогда процесс аварийно завершится с ошибкой нарушения целостности стека.

Мы не пытались эксплуатировать переполнение, так что смотрим ещё раз на стек и видим что защищает канарейка:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241225004139.png)

Канарейка со значением `0x691605e5eced100` находится до значений `0x1` и `0x00007ffff7da6d90`. Второе — адрес возврата. 

В нашем случае — адрес внутри стандартной библиотеки С:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241226003212.png)

Если передать больше 100 байт, канарейка повредится. Это приведёт к ошибке при проверке:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241226004019.png)

Мы передали 128 символов `a`, получили переполнение стека и перезапись канарейки. Поскольку значение в регистре `rdx`  содержит наши данные, и они не равны данным, которые находятся в регистре `fs`, мы попадем в функцию `__stack_chk_fail`. 

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241226004407.png)

Из нее мы достанем строку по адресу внутри libc и передадим ее аргументом в функцию `__GI___fortify_fail`:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241226010609.png)

Далее получим сообщение, что стек был повреждён и процесс завершает работу. Завершение работы происходит через отправку сигнала `SIGABRT` процессу:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241226011019.png)

Так работает канарейка. 
Теперь разберемся как она появляется в регистре `fs:0x28` и что это вообще за регистр. 

# Регистр FS

FS — это сегментный регистр. В Linux user space используется для хранения указателя на структуру TLS (Thread Local Storage). 
Подробнее об этом можно почитать в [официальной документации Linux](https://docs.kernel.org/arch/x86/x86_64/fsgs.html). Там же можно найти информацию, как записываются данные в FS и как туда помещается указатель на TLS.

Чтобы посмотреть регистр вводим в GDB команду:
```
gef➤ i r $fs_base
```

Получаем адрес TLS:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229192958.png)

В процессе эта память лежит сразу после образа исполняемого файла и перед libc:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229193236.png)

<details>
<summary>Примечание на полях</summary>
*Заметим, что сразу после этой страницы начинается libc. Значит между ними нет расстояния. Если вы знаете адрес загрузки libc, то вы можете узнать где располагается TLS. Это интересный факт, который может быть полезен для эксплуатации.* 
</details>

# TLS и TCB

Содержимое TLS документировано и мы можем просмотреть поля структуры в отладчике с помощью команды:
```
gef➤ p *(tcbhead_t*)$fs_base
```

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229200347.png)

Обратите внимание, что структура называется `tcbhead_t`. Это потому, что TLS определяет технологию, а TCB (Thread Control Block) — конкретный блок данных. 
TLS может быть реализована по-разному в различных системах — это лишь метод организации данных для потока.

Поле `stack_guard` содержит канарейку. Она хранится в той же памяти что и процесс. Это значит, что мы можем узнать её адрес и переписать.

Однако стоит учесть, что если переписать канарейку в TCB, придётся переписать её и в функциях выше, чтобы успешно из них выйти. На стеке вызовов останутся старые канарейки из TCB. 

Это не критично, если вы переписываете канарейку в TCB и потом переписываете ее на стеке, а сразу после начинается ваша ROP-цепочка. Но об этом стоит помнить.

# Как инициализируется значение

Канарейка записывается при помощи [макроса](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/sysdeps/x86_64/nptl/tls.h#L194) `THREAD_SET_STACK_GUARD`:
```c
/* Set the stack guard field in TCB head. */
...
THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```

 [Этот макрос](https://elixir.bootlin.com/glibc/glibc-2.20/source/csu/libc-start.c#L201) используется так:
 
![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229210501.png)

Функция `_dl_setup_stack_chk_guard` генерирует канарейку. Далее в зависимости от условий она записывается в TLS или глобальную переменную. 

Изучим [функцию генерации канарейки](https://elixir.bootlin.com/glibc/glibc-2.20/source/sysdeps/generic/dl-osinfo.h#L23):
```c
static inline uintptr_t __attribute__ ((always_inline))
_dl_setup_stack_chk_guard (void *dl_random)
{
  union
  {
    uintptr_t num;
    unsigned char bytes[sizeof (uintptr_t)];
  } ret = { 0 };

  if (dl_random == NULL)
    {
      ret.bytes[sizeof (ret) - 1] = 255;
      ret.bytes[sizeof (ret) - 2] = '\n';
    }
  else
    {
      memcpy (ret.bytes, dl_random, sizeof (ret));
#if BYTE_ORDER == LITTLE_ENDIAN
      ret.num &= ~(uintptr_t) 0xff;
#elif BYTE_ORDER == BIG_ENDIAN
      ret.num &= ~((uintptr_t) 0xff << (8 * (sizeof (ret) - 1)));
#else
# error "BYTE_ORDER unknown"
#endif
    }
  return ret.num;
}
```

Копируем байты из указателя `dl_random`, после зануляем первый байт. Данные в `dl_random` — указатель на случайные байты, которые получаем от ядра при запуске процесса. В последних версиях libc механизм назначения этого указателя был изменён. Можно отследить где инициализируется `_dl_random` так как это глобальная переменная. 

Для этого используем аппаратные брейкпоинты:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229225550.png)

Остановимся внутри загрузчика в функции `_dl_sysdep_parse_arguments`:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020241229225723.png)

Изучив [код](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/dl-sysdep.c#L77) видим, что функция `_dl_parse_auxv` подставилась во время компиляции в место вызова. На самом деле инициализация переменной `_dl_random` происходит в [строке 54](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/dl-parse_auxv.h#L54):
```c
static inline
void _dl_parse_auxv (ElfW(auxv_t) *av, dl_parse_auxv_t auxv_values
{
...skip...
for (; av->a_type != AT_NULL; av++)
	if (av->a_type <= AT_MINSIGSTKSZ)
		auxv_values[av->a_type] = av->a_un.a_val;
...skip...
_dl_random = (void *) auxv_values[AT_RANDOM];
```

Значение `_dl_random` берётся из массива `auxv_values`. Этот массив инициализируется полями структуры `auxv_t`. Объект структуры передаётся в функцию первым аргументом.  В коде вызывающей функции `_dl_sysdep_parse_arguments` можно найти какой именно аргумент передаётся:
```c
static void
_dl_sysdep_parse_arguments (void **start_argptr,
			    struct dl_main_arguments *args)
{
  _dl_argc = (intptr_t) *start_argptr;
  _dl_argv = (char **) (start_argptr + 1); /* Necessary aliasing violation.  */
  _environ = _dl_argv + _dl_argc + 1;
  for (char **tmp = _environ; ; ++tmp)
    if (*tmp == NULL)
      {
	/* Another necessary aliasing violation.  */
	GLRO(dl_auxv) = (ElfW(auxv_t) *) (tmp + 1);
	break;
      }

  dl_parse_auxv_t auxv_values = { 0, };
  _dl_parse_auxv (GLRO(dl_auxv), auxv_values);
```

Переменная `dl_auxv` инициализируется адресом на конец массива указателей на переменные окружения. Переменные окружения — результат арифметики указателей. При этом оба указателя зависят от первого аргумента функции. 

Посмотрим на стек вызовов в этот момент:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250102012601.png)

Аргумент передаётся из функции в функцию и берёт своё начало в `_dl_start`. Эту функцию вызывает код из `_start` — это точка входа в процесс, запускаемый ядром ОС. То есть это самый первый код, который будет выполнен после запуска процесса.

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250102013517.png)

На стеке уже будут находиться некоторые данные. Они появились потому что ядерный код их инициализировал. В том числе и специальный массив, который лежит после указателей на переменные окружения. Он называется [Auxiliary Vector](https://www.gnu.org/software/libc/manual/html_node/Auxiliary-Vector.html). 

Можно найти [код в ядре](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c#L257) который отвечает за его генерацию:
```c
get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
u_rand_bytes = (elf_addr_t __user *) STACK_ALLOC(p, sizeof(k_rand_bytes));

if (copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
	return -EFAULT;
	...skip...
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
	...skip...
```

Ядерный код получает случайные 16 байт через функцию `get_random_bytes`, после чего записывает их в массив. Массив будет находиться на стеке процесса. Следовательно, вы можете найти канарейку на стеке после переменных окружения. 

На изображении ниже сначала получаем канарейку из TCB, а потом находим её на стеке:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250102015046.png)

Из этого следует, что если у вас есть какой-то примитив позволяющий читать стек после переменных окружения, можно достать канарейку.
# Особенности
Хотим отметить несколько интересных фактов, которые могут быть не вполне очевидны из описанной информации:
1. Канарейка генерируется для нового процесса запускаемого через `execve`, но если мы используем `fork` то память будет скопирована и мы получим аналогичную канарейку в новом процессе. Это можно использовать для перебора по байту через ошибку повреждения стека.
2. 1 байт канарейки всегда известен и это `0x00`. Он нужен для ситуаций когда перед канарейкой может оказаться строка без терминирующего нуля и тогда в функции работы со строками потенциально попадали бы байты канарейки. 

# Обходы

Мы рассказали как работает канарейка: как она появляется и где её можно найти. Теперь выделим пути обхода этой защиты.

1. Произвольное чтение стека
Если есть уязвимость, позволяющая читать любые данные со стека — можно получить канарейку через чтение стекового фрейма функции.

2. Перезапись значения эталонной канарейки в TCB с переполнением буфера на стеке в текущей функции

3. Чтение стека от переменных окружения вниз по стеку

4. Перебор канарейки
Перебрать канарейку напрямую невозможно. Но если есть примитив, позволяющий переписать 1 байт и не привести к полному завершению работы процесса, это может сработать. Например, если использовать `fork`.

Однако любой из описанных способов обхода — редкая и уникальная, но все же возможная ситуация. Канарейка сильно снизила количество успешных эксплуатаций переполнения буфера на стеке.

В следующей части мы разберём реализацию канарейки в ядре Linux. 

## Стековая канарейка в ядре Linux

Базовый принцип работы стековой канарейки в ядре точно такой же, как и в пользовательском пространстве. Основное отличие в том, что канарейка здесь генерируется один раз при инициализации.

На скриншоте ниже показано что реализация функции генерации канарейки зависит от архитектуры процессора.

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250202010435.png)

Мы посмотрим [реализацию](https://elixir.bootlin.com/linux/v6.13/source/arch/x86/include/asm/stackprotector.h#L50) для x86.

```c
static __always_inline void boot_init_stack_canary(void)
{
	unsigned long canary = get_random_canary();

#ifdef CONFIG_X86_64
	BUILD_BUG_ON(offsetof(struct fixed_percpu_data, stack_canary) != 40);
#endif

	current->stack_canary = canary;
#ifdef CONFIG_X86_64
	this_cpu_write(fixed_percpu_data.stack_canary, canary);
#else
	this_cpu_write(__stack_chk_guard, canary);
#endif
}
```

Возьмем функцию `get_random_canary()` и её результат запишется в глобальную переменную, которая будет использоваться на ядерном стеке для его защиты.

Функция получения канарейки выглядит [так](https://elixir.bootlin.com/linux/v6.13/source/include/linux/stackprotector.h#L23).

```c
#ifdef CONFIG_64BIT
# ifdef __LITTLE_ENDIAN
#  define CANARY_MASK 0xffffffffffffff00UL
# else /* big endian, 64 bits: */
#  define CANARY_MASK 0x00ffffffffffffffUL
# endif
#else /* 32 bits: */
# define CANARY_MASK 0xffffffffUL
#endif

static inline unsigned long get_random_canary(void)
{
	return get_random_long() & CANARY_MASK;
}
```

Функция `get_random_long()` возвращает случайное значение в зависимости от размера указателя. Для получения случайного значения используется функция `get_random_bytes()`, с которой мы уже знакомы.

Так это выглядит в скомпилированном ядре и вот куда конкретно записывается канарейка:
![](/assets/Stack-Canary-Internals/Pasted%20image%2020250407003117.png)

Мы записываем канарейку по смещению 0x28 от некоторого регистра GS. 

Если вернуться к исходному коду и посмотреть куда пишем канарейку, то выйдем на структуру `fixed_percpu_data`.

```c
struct fixed_percpu_data {
	/*
	 * GCC hardcodes the stack canary as %gs:40.  Since the
	 * irq_stack is the object at %gs:0, we reserve the bottom
	 * 48 bytes of the irq stack for the canary.
	 *
	 * Once we are willing to require -mstack-protector-guard-symbol=
	 * support for x86_64 stackprotector, we can get rid of this.
	 */
	char		gs_base[40];
	unsigned long	stack_canary;
};
```

Именем этой структуры также называется глобальная переменная, где лежит канарейка. 
Можно обратить внимание на комментарии, а ещё на вот на [это обсуждение](https://lore.kernel.org/lkml/20231023211730.40566-1-brgerst@gmail.com/T/), в котором проливается свет на довольно прикольный факт.

Дело в том, что компилятор GCC зарезервировал за собой право использовать для стековой канарейки регистр GS по смещению 0x28. А в ядре этот регистр в том числе используется для хранения объекта `irq_stack` который представляет собой дополнительный стек обработки аппаратных прерываний.

Инициализация значения регистра GS происходит в самом начале запуска ядра. Представляет собой чтение значения из регистра MSR. 
[Сниппет](https://elixir.bootlin.com/linux/v6.13/source/arch/x86/kernel/cpu/common.c#L744) кода:

```c
void __init switch_gdt_and_percpu_base(int cpu)
{
	load_direct_gdt(cpu);
#ifdef CONFIG_X86_64
	/*
	 * No need to load %gs. It is already correct.
	 *
	 * Writing %gs on 64bit would zero GSBASE which would make any per
	 * CPU operation up to the point of the wrmsrl() fault.
	 *
	 * Set GSBASE to the new offset. Until the wrmsrl() happens the
	 * early mapping is still valid. That means the GSBASE update will
	 * lose any prior per CPU data which was not copied over in
	 * setup_per_cpu_areas().
	 *
	 * This works even with stackprotector enabled because the
	 * per CPU stack canary is 0 in both per CPU areas.
	 */
	wrmsrl(MSR_GS_BASE, cpu_kernelmode_gs_base(cpu));
#else
	/*
	 * %fs is already set to __KERNEL_PERCPU, but after switching GDT
	 * it is required to load FS again so that the 'hidden' part is
	 * updated from the new GDT. Up to this point the early per CPU
	 * translation is active. Any content of the early per CPU data
	 * which was not copied over in setup_per_cpu_areas() is lost.
	 */
	loadsegment(fs, __KERNEL_PERCPU);
#endif
}
```

Мы можем проверить это в отладке ядра. Найдём для начала адрес переменной `per_cpu_offset` где хранится адрес куда указывает GS регистр:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250407014238.png)

Проверим что лежит по нашему адресу и что лежит в регистре `gs_base`:
![](/assets/Stack-Canary-Internals/Pasted%20image%2020250407014311.png)

Всё корректно.
Теперь проверим, что по смещению 0x28 действительно лежит канарейка:

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250407014444.png)

И это тоже верно. 
Также хочется обратить внимание на то, что страницы куда указывается регистр GS имеют права RW, а это означает, что потенциально возможна атака с перезаписью канарейки. 
Но если у вас есть возможность писать по любому адресу в ядре, вряд ли вы будете заморачиваться с перезаписью канарейки.

![](/assets/Stack-Canary-Internals/Pasted%20image%2020250407014724.png)

# Итого
Базовая идея реализации канарейки в ядре очень схожа с user space. Мы берём случайные 8 байт и записываем их в некоторое смещение относительно сегментного регистра. Значение регистра мы берём из регистра MSR.

Что касается обходов, то здесь есть только один реалистичный вариант — утечка памяти.

В следующей части мы разберём реализацию стековой канарейки в Windows user space.

*Больше райтапов и материалов по пывну в [телеграм канале](https://t.me/sploitdev)*
