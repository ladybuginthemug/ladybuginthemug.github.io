---
draft: false
author: ladybuginthemug
title: malicious power-shell analysis
description: The challenge provide a file containing obfuscated malicious power-shell code, our job is to de-obfuscate/decode and investigate the goals the bad actor set behind it, answering questions along the way.
date: 2023-08-14
category:
  - blueteamlabs
---
#blueteamlabs 

This is my first write-up on [https://blueteamlabs.online](https://blueteamlabs.online) challenge “**Malicious power-shell analysis“.**

The challenge provide a file containing obfuscated malicious power-shell code, our job is to de-obfuscate/decode and investigate the goals the bad actor set behind it, answering questions along the way.

## Examination

First thing first, we open the file with any preferred text editor(Sublime, Notepad, etc.).

The ‘POwersheLL -w hidden -ENCOD’ at the beginning. Despite odd capitalization, — when you type in PowerShell, you don’t have to worry about whether letters are big or small. What’s more important are the instructions it gives. When it says ‘-w hidden’, it tells PowerShell to open up a hidden window. And that ‘-ENCOD’ part is just a quick way to say “encoded.” The rest of it is a pretty long obfuscated code that needs to be decoded.

![](https://miro.medium.com/v2/resize:fit:700/1*ILU5_HTaYpPt0n2obKeqRg.png)

By looking up close at provided obfuscated code, we can pretty easily spot that the first layer is encoded with `base64`
___

> What is `base64`? _Base64_ is a binary-to-text encoding scheme. It's represented as ASCII characters where each Base64 character contains 6 bits of binary information.
> 
> In Base64, as the name suggests, there are 64 characters used to encode binary data. These characters are:
> 
> 26 Capital letters [A-Z]
> 
> 26 lower letters [a-z]
> 
> 10 digits [0–9]
> 
> 2 special characters [+ , /]
> 
> **Note:** If the length of the data is not a multiple of three, some extra handling is needed to encode the remaining bytes. There is 65th character (`=`) to ensure that the encoded data is properly aligned and can be decoded correctly. It's called a _padding character_ used to indicate that no further bits are needed to fully encode the input.

_________________________________

We can decode it using Power shell or CyberChef ( [git link here](https://github.com/gchq/CyberChef) ).

I will go with Power shell here.


### Decode base64


```bash
echo "encoded data" | base64 --decode >> decoded_from_base64.txt

```


Run the command and open a new file for further investigations. ( Or copy results in your preferred location )

![](https://miro.medium.com/v2/resize:fit:700/1*24WZA3oXl3OD3dF7vOA-1A.png)



Now things start looking much more code-like. But let’s make it even better.

If you stare long enough you start to see patterns. Seems to me that everything after `;` char we could treat as a new line and we can clean up a bunch of unnecessary characters like backticks `` ` ``.

To filter that we would use `regex` ( regular expressions ). You can do that using CyberChef too.

But I will go with python here. That script will do just that and create a new `txt` file with output.
________________________________

## Using regex expressions to parse strings out of text


```python
#!/usr/bin/env python  
  
import sys  
import re  
# Check if the input file is provided as a command-line argument  
if len(sys.argv) < 2:  
    print("Usage: python script.py <input_file>")  
    sys.exit(1)  
# Get the input file path from the command-line argument  
input_file_path = sys.argv[1]  
# Read the input file  
with open(input_file_path, 'r') as file:  
    input_text = file.read()  
# Find all matches of the pattern in the input text  
first_matches = re.sub(r"[`]", '', input_text)  
# Join the matches into a single string  
text = ''.join(first_matches)  
# We replacing all ";" to make code format more readable   
matches = re.sub(r"[;]", ';\n', text)  
# Join the matches again  
output_text = ''.join(matches)  
# Derive the output file path from the input file path  
output_file_path = input_file_path.replace('.txt', '_output.txt')  
# Write the output to a file  
with open(output_file_path, 'w') as file:  
    file.write(output_text)  
print("Output written to " + output_file_path)

```

Now, that looks better !

![](https://miro.medium.com/v2/resize:fit:700/1*4k-h0rasjjZiggiuqT4Dnw.png)



The first lines of code that are starting with `‘set Mku’` and `‘Set-Item’` are setting some variables that are obfuscated by splitting them and reordering their positions . Provided `{0}{1}{2}{4}{3}` and `{6}{8}{0}{3}{4}{5}{2}{7}{1}` are the instructions (mappings) of how to build them back together.


```Shell

echo ("{0}{1}{2}{4}{3}" -f 'syst','em.','io.di','ory','rect') | out-string  
system.io.directory  
  
echo ("{6}{8}{0}{3}{4}{5}{2}{7}{1}" -f'stem','ger','ma','.n','et.servicepoi','nt','s','na','y')  
system.net.servicepointmanager

```


Next line setting `ErrorActionPreference` to pretty readable`‘Silently Continue’.` It sets code in stealthy mode, suppressing any errors if they pop up.


```bash
$ErrorActionPreference = (('S'+'il')+('en'+'t')+'ly'+('Cont'+'i'+'nue'));

```


_______________________

### What directory does the obfuscated PowerShell create? (Starting from \HOME\)

We are lucky, we can finally spot variables with exactly what we looking for. `( DIr VariabLE:Mku ).VaLUe::”cREAtedIRECTORy”.`We can see the beginning of the path $HOME, while everything after that looks like gibberish, it is not quite is. The path has been obfuscated using concatenation `+` and character obfuscation. At the end, there is a hint `-F [char]92` which indicates that something was encoded with ASCII character 92. We can look up the character in ASCII table and it is `\`. We know that this is a path so we can safely assume that symbol `\` is obfuscated with `{0}`.

![](https://miro.medium.com/v2/resize:fit:217/1*G04jk6cTA0OKBeNhCJm7ig.png)


```python
{0} = [chAR]92 = \
```


Now once we learned what the deal is. You can do reversing manually or you can throw the command below in power-shell and get the answer.


```bash
echo (('{'+'0}Db_bh'+'30'+'{0}'+'Yf'+'5be5g{0}') -F [chAR]92)
```


`Answer` \Db_bh30\Yf5be5g\
________________________
### What security protocol is being used for the communication with a malicious domain?

We can spot our answer on `line 8`. No extravaganza is needed here. We can visually concatenate the value of `security protocol = TLS 1.2.`

Transport Layer Security (TLS) is designed to provide communications security by encrypting data between two endpoints.


```bash
"sEcuRITYproTocol" = ('T'+('ls'+'12'))
```


`Answer` **TLS 1.2**
______________
### What file is being downloaded (full name)?

Well, again we are dealing with path. We can found begging of it again by spotting `$HOME` at `line 12` . We need to replace `UOH` with `char[92]`which we learned by now is `\` and concatenate.

![](https://miro.medium.com/v2/resize:fit:700/1*TZ83Tk9KEgnFe0Y0Vkhk-w.png)

$Imd1yck = $HOME + "\Db_bh30\Yf5be5g\" + $Swrp6tc + (('.'+'dl')+'l')

At the end of the string is variable `$Swrp6tc` is assigned to `A69S (line 10)` with apparent file extension `+(('.'+'dl')+'l')= dll`.

A malicious DLLs , short for Dynamic Link Library, can be used in many ways to provide unauthorized access and corruption of the victim’s system.

```bash
$Swrp6tc = (('A6'+'9')+'S')   
$Swrp6tc += (('.'+'dl')+'l')
```


![](https://miro.medium.com/v2/resize:fit:1000/1*lDTNc8IErB0i02zwOVJuqg.png)

`Answer` A69S.dll
________________________
### What is the domain name of the URI ending in ‘/6F2gd/’ ?

We can see that there are some signs that assignments to variable `$B9fhbyv` are URLs. To decode we need to look up instructions and we can spot one - `‘Replace ’`.

It is direct us to replace `']anw[3'` with `array[1]` which is `'http'` and concatenate.

![](https://miro.medium.com/v2/resize:fit:1000/1*XvzH3A1YDLVT1oV7lzAobA.png)

We can do that manually or we can echo encoded value into Powershell and have the results.

![](https://miro.medium.com/v2/resize:fit:700/1*Zcoot4i4kg6QZyA1mtizJw.png)

The malware attempts to connect to and obtain additional content, probably malicious DLLs. The domains are found to be malicious, which is why they have been defanged .

`Answer:` wm[.]mcdevelop[.]net
______________________________________
### What is used to execute the downloaded file?

And…We continue to concatenate.

After it goes through each web address in the list and tries to download `dlls files` from that address to the specified location (`$Imd1yck`). The code evaluates if the size of the downloaded file is larger than or equal to 35698 bytes. if true it runs the file as a command and it uses rundll32, which loads and runs 32-bit dynamic-link libraries (DLLs)

![](https://miro.medium.com/v2/resize:fit:700/1*kHJEpVqetSyaO6DST2DryA.png)

![](https://miro.medium.com/v2/resize:fit:596/1*ne2V3DWlQQD_jSxcymf7_A.png)

{&('r'+'undl'+'l32')

`Answer` rundll32
__________________
### Based on the analysis of the obfuscated code, what is the name of the malware? 

By investigating URLs used for downloading malicious droppers with a site like **Virus Total or MalwareBazaar** we can conclude that this is `emotet.` Emotet is a trojan that is typically spread through spam emails. The trojan module is capable of loading and installing additional malware, stealing online credentials and personal sensitive information.

`Answer`: **👾 emotet**
_____________________________

## Updated python code

Once we learned about techniques used in the obfuscation of the code we can ease the pain of manual extraction of the code with an updated python script.

Some cleaning will still be needed, though. ( I would use the script with updated first two lines of code since script will break that part)


```python
#!/usr/bin/env python  
  
import sys  
import re  
# Check if the input file is provided as a command-line argument  
if len(sys.argv) < 2:  
    print("Usage: python script.py <input_file>")  
    sys.exit(1)  
# Get the input file path from the command-line argument  
input_file_path = sys.argv[1]  
# Read the input file  
with open(input_file_path, 'r') as file:  
    input_text = file.read()  
  
# Concatenating the strings together and cleaning unnecessary symbols  
first_matches = re.sub(r"(?:\'\)\+\(\')|(?:\'\+\')|(?:\'\)\+\')|(?:\'\+\(\')|(?:\`|\'\,\')|(?:\"\+\")|\)|\(", '', input_text)  
# Join the matches into a single string  
text = ''.join(first_matches)  
# Inserting new line after ';' and '@'.  
second_matches = re.sub(r"[;|@]", ';\n', text)  
text = ''.join(second_matches)  
# replacing ]anw\[3 with de-fanged http since the links are malicious.  
third_matches = re.sub(r"(?:\]anw\[3)", 'hxxp', text)  
text=''.join(third_matches)  
fourth_matches = re.sub(r"(?:w{3})", '[www]', text)  
text=''.join(fourth_matches)  
#replacing '{0}' and 'UOH' with '/'  
fifth_matches = re.sub(r"(?:\{0\})|(?:UOH)", '/', text)  
text=''.join(fifth_matches)  
# Derive the output file path from the input file path  
output_file_path = input_file_path.replace('.txt', '_output.txt')  
# Write the output to a file  
with open(output_file_path, 'w') as file:  
    file.write(text)  
print("Output written to " + output_file_path)

```


![](https://miro.medium.com/v2/resize:fit:700/1*3agw8WpEaOHTwhuvfxXjRA.png)

I went further to investigate/clean-up as far as I could the rest of it.

De-obfuscated code looks like that:

![](https://miro.medium.com/v2/resize:fit:700/1*UWmcjYAyZfTEYLHXYMmj-Q.png)

# Summary:

1. It sets up some variables and configurations for later use, also setting `ErrorActionPrefence` to `silently continue` making any execution errors pass in stealthy mode.
2. It creates a directory (folder) using the `$Home` variable as the base path and adds a specific folder structure.
3. It sets a security protocol for communication to ensure it’s secure.
4. It defines a list of web addresses (`$B9fhbyv`).
5. It goes through each web address in the list and tries to download `DLLs files` from that address to the specified location (`$Imd1yck`).
6. If the downloaded file’s size is larger than or equal to 35698 bytes, it runs the file as a command.
7. If the file execution is successful, it breaks out of the loop.
8. Finally, the code ends, and the script is completed.
