# Description

The RE has to find the button handler of the play button.  
Here he has to apply two patches:  

```asm
mov dl,1  
mov rcx,qword ptr ds:[rbx+50]  
call crackme.7FF617FC36F0  
mov dl,1  
mov rcx,qword ptr ds:[rbx+50]  
call crackme.7FF617FC3710  
```

Patching both `mov dl,1` to `mov dl,0` will fix the record player and display the flag while playing the song.  

# Supported OS

Tested on Windows 10.  

# Architecture

x86-64  

# Language

C/C++  

# Flag

CMO{y0u_g0t_r1ckr0ll3d}
