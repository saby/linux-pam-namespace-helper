Linux-pam-namespace-helper
====================================
Модуль для работы СБИС Плагина в условиях включенного мандатного доступа для директории шареной памяти /dev/shm.

# Содержание
- [Сборка](#сборка)
- [Установка](#установка)

# Сборка
```
make -f MakeFile
```
# Установка
1. Собранный артефакт pam_saby_helper.so нужно разместить в директории /lib64/security/

   ```
   sudo mv pam_saby_helper.so /lib64/security/
   ```
2. В директории /etc/pam.d нужно найти файлы сценариев, в которых включен модуль мандатного доступа. Сделать это можно командой
   1. Если у вас AltLinux
      ```
      grep -R pam_namespace.so /etc/pam.d​
      ```
   2. Если у вас AstraLinux
      ```
      grep -R pam_parsec_mac.so /etc/pam.d
      ```
3. В найденных файлах нужно добавить включение собранного ранее модуля pam_saby_helper.so перед включением pam_namespace.so или pam_parsec_mac.so, в зависимости от дистрибутива
   ```
   session         optional        pam_saby_helper.so
   ```
4. Необходимо перезапустить систему.