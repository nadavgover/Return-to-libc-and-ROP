# Return to libc and Return Oriented Programming (ROP)

## Background (and some history)

Most buffer overflow attacks rely on writing our code into the
stack and then hijacking the flow of the program to execute our code. After this sort
of attacks became popular, some security measures were taken to make it harder to
carry out these attacks.
During 2000-2005, many operating systems began implementing various
protections on the executable space, typically by marking the stack (and/or other
areas of the memory) as non-executable. This prevented the classic buffer overflow
attack we exploited so far, and presented a new challenge for attackers.
In 2006, an attack called return-to-libc was published, describing a mechanism that
enables obtaining a shell in some cases, even with a non-executable stack. This
technique was implemented in the first part of the project.
In 2007, a significantly improved version of this attack was published under the
name return oriented programming (ROP). This was presented in Blackhat 2008,
and enabled executing far more sophisticated codes than return-to-libc. This
technique was implemented in the second part of the project.
Our target in this project is the sudo program. It has a
non-executable stack so regular BOF attack won't work.

## Inspecting libc memory with GDB
Before starting to implement return to libc, we’ll need to understand how to inspect the
memory of libc (the C standard library).

We can do this with GDB and specifically the `info files` command and look for text sections in libc. The important part is that 
this section of the memory is executable.

## Gadget search engine
In the second part of the project we’re going to implement ROP attacks! However,
implementing a ROP requires having a working “gadget search engine” that can
search the memory and locate gadgets! It will support searching for the same instruction with multiple combinations of
registers at once, so that we don’t have to try all combinations manually. For
example:

<img src="/gadget_search_example.JPG" width="500" alt="gadget search example">

Now we are ready to implement ROP.













