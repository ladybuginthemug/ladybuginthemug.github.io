---
draft: false
author: ladybuginthemug
title: BTLO File Carving
description: John received the 'Best Employee of the Year' award for his hard work at FakeCompany Ltd. Unfortunately, today John deleted some important files (typical John!). It’s your job to recover the deleted files and capture all the flags contained within!
date: 2024-01-05
category:
  - blueteamlabs
---

[Employee of the Year](https://blueteamlabs.online/home/challenge/employee-of-the-year-df16bc36f3)

> Scenario
>
>John received the 'Best Employee of the Year' award for his hard work at FakeCompany Ltd. Unfortunately, today John deleted some important files (typical John!). It’s your job to recover the deleted files and capture all the flags contained within!


The file given is `recoverfiles.dd`. To begin, you need to gain an understanding of the structure of the disk image and the file system it contains. 

The `mmls` command provides details about the disk image structure, indicating that:

- it has a DOS partition table with one partition. 
- the partition starts at sector 2048 and contains an Ext4 file system with a Linux operating system.

```bash
└─$ mmls recoverfiles.dd 
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048 Unallocated
002:  000:000   0000002048   0000020479   0000018432   Linux (0x83)
```                  

The `fsstat` command with the correct offset `2048` provides additional file system information, such as the file system type `Ext4`, volume name, volume ID, and other details.
```bash
└─$ fsstat -o 2048 recoverfiles.dd 

FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: 
Volume ID: 619b3a18aabdc1a6a44a07e931710220

....
....
....

```

`fls` lists the files and directories and with that, we learned original file names and clues for future investigation. 

```bash
└─$ fls -o 2048 recoverfiles.dd
d/d 11: lost+found
r/r * 12:       Vanilla.gif
r/r * 13:       SBTCertifications.mp4
r/r * 14:       Flag3.pdf
r/r * 15:       Flag2.docx
r/r * 16:       Flag1.png
V/V 2305:       $OrphanFiles
```

---

It's time to recover files, with the use of `photorec`. This interactive tool allows you to select the correct file system, partition, and the specific files you want to recover. :

```bash
└─$ photorec recoverfiles.dd

PhotoRec 7.1, Data Recovery Utility, July 2019
Christophe GRENIER <grenier@cgsecurity.org>
https://www.cgsecurity.org
```
![photorec](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/580a238b-d606-4d9e-b4fc-24239987915d)

Then it will attempt to recover files and output them in your chosen location. And just like that the files are recovered. 


![files_rec](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/5942a645-9c1f-4769-a0b7-1edc6a1e6ca7)

---

It is easy to search for the first flag, which is simply displayed in the recovered `gif` image :
![first](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/5dc8c1db-99a3-4c19-afc8-9c3c37a1b1fc)


The next flag is also hiding in plain sight in the recovered `png`:

![second](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/83f2d8d2-b8a0-4f50-9342-b08e4ab83259)

---

Exploring `pdf` file makes us realize that `flag3` is probably hiding within the file itself. 

![pdf](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/9c4dc63e-f195-447a-9610-af8e1fc77f91)


Using `exiftool` on that pdf file will reveal the answer

```bash
ExifTool Version Number         : 12.67
File Name                       : f0009040.pdf
Directory                       : .
File Size                       : 13 kB
File Modification Date/Time     : 2024:01:05 19:14:09-05:00
File Access Date/Time           : 2024:01:07 17:38:13-05:00
File Inode Change Date/Time     : 2024:01:05 19:14:09-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Author                          : FLAG3%3A%40BLU3T3AM%240LDI3R
Producer                        : Skia/PDF m90
Page Count                      : 1
                                          
```

using `strings` works too. 

```bash
└─$ strings f0009040.pdf | grep 'FLAG'  
/Author (FLAG3%3A%40BLU3T3AM%240LDI3R)

```

The string is slightly obfuscated or `URL-encoded`. You can decode it with CyberChef or go fancy: 

```bash
└─$ python3 -c "import urllib.parse; print(urllib.parse.unquote('FLAG3%3A%40BLU3T3AM%240LDI3R'))"
FLAG3:@BLU3T3AM$0LDI3R

```
---

Okay, move on to the `FLAG2` that is in `f0009072.docx` file, according to the original names of the files. 

There are a few ways it's possible to retrieve a hidden string from that document the easiest way to extract the text content from a DOCX file:

1. you can use the `docx2txt` tool. This command will create a text file containing the extracted text content from the DOCX file.: 

```bash
└─$ docx2txt f0009072.docx | cat f0009072.txt 

RkxBRzI6QVNPTElEREVGRU5ERVI=

```

2. Since **docx** **files** **are** **zipped** collections of XML files, the unzip command will help:
```bash
└─$ unzip f0009072.docx 
Archive:  f0009072.docx
  inflating: word/numbering.xml      
  inflating: word/settings.xml       
  inflating: word/fontTable.xml      
  inflating: word/styles.xml         
  inflating: word/document.xml       
  inflating: word/_rels/document.xml.rels  
  inflating: _rels/.rels             
  inflating: word/theme/theme1.xml   
  inflating: [Content_Types].xml 
```

Then you can search manually XML documents and find the flag in document.xml. Which is boring. 

![xml](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/800af69d-407f-480a-8662-ffaf29ab62de)


or use strings piped with grep in combination with regex.

```bash
└─$ strings f0009072.docx word/*.xml | grep -E '>[^<>]+<'
```
![grep](https://github.com/ladybuginthemug/ladybuginthemug.github.io/assets/88084724/f5e0fa2b-54b5-4abc-81da-bce12bfd29ed)

This flag is also obfuscated in the most common way `base65`:

```bash
└─$ echo -n 'RkxBRzI6QVNPTElEREVGRU5ERVI=' | base64 -d

FLAG2:ASOLIDDEFENDER   
```

