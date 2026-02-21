# crackmes_one_ctf

## Challenge description
No matter where you go, everybody's connected.

## The flag
- The correct user message (the "what"): `msg_:"*$$*":`
- The correct destination (the "where"): `100.25.26.10`

Providing the correct values prints out the flag: `CMO{secret_code_v9hcdkd2}`

---

## About the challenge
The crackme revolves around PCs, routers and switches. The switches communicate at a L2 level (ethernet frames) and the routers at L3 level (IP packets). They send around frames and packets. Think of a real network in a way. The format of these frames and packets is not realistic though.

The idea is, that the input of the player is interpreted in the following manner:
1. IP-address of the target system
2. Message that the target system either accepts or does not accept. The answer is sent from the target PC back to the PC of the user.

The challenge is also split up between multiple systems as follows:
1. The user is prompted for `what: ` and `where: `
2. The `where` field is interpreted as an IP-address and the `what` is sent there
3. Different recipients have different responses (which should be printed out), but if the target system receives the message, it starts processing it
4. The target system sends out pieces of the message to other systems for processing. Those systems will then immediately respond with the result. Only messages sent to the user pc are printed out to the console.

## The intended solution
1. The user sends the `what` and `where` to the target pc (100.25.26.10).
2. The target pc does the following things:
    1. Check if the sender was the user
    2. Verify that the message begins with the magic bytes `msg_`
    3. Strip the `msg_` magic bytes from the beginning of the message
    4. Send the message to PC9 (83.48.92.8). The PC9 XORs anything it receives with 0x42 and sends the data back to whoever sent it the data
    5. Send the XOR encoded data to PC3, PC4 and PC7 and wait for their responses
3. The PC3 (64.14.3.25) will do the following things with the data it receives:
    1. Send the data to PC9 to undo the XOR cipher (or to XOR the received data in case the user sends this PC data)
    2. Calculate the character count in the string
    3. Return the count to whoever sent it the original packet
4. The PC4 (64.14.3.29) will do the following things with the data it receives:
    1. Send the data to PC9 to undo the XOR cipher (or to XOR the received data in case the user sends this PC data)
    2. Calculate the adler32 checksum for the string
    3. Calculate the fletcher16 checksum for the string
    4. XOR both checksums together
    5. Check if the string is a palindrome and multiply the XOR result with the boolean value
    6. Calculate another position dependent XOR based checksum to reduce collisions. XOR the previous checksum value with this value.
    7. Return the result to whoever sent the original packet
5. The PC7 (100.25.26.15) will do the following things with the data it receives:
    1. Send the data to PC9 to undo the XOR cipher (or to XOR the received data in case the user sends this PC data)
    2. Check if all characters in the string have an even numeric value
    3. Check if all characters in the string are printable
    4. Send the combined result back as a boolean 0 or 1 to the sender of the packet
6. When the target pc receives the results from PC3, PC4 and PC7, it does the following things:
    1. Check if the data received from PC3 (string length) is equal to 8
    2. Check if the data received from PC7 is equal to 1 (all chars were even and printable)
    3. Check if the received hash equates to a specific value
    4. If everything matches up, send the original user message (without the magic bytes) to PC1
        - Whenever PC1 receives a packet from anyone other than the user, it formats it into a flag and sends that to the user
        - If PC1 receives something from the user, it responds with `My complicated firewall rules told me to not talk to you`
    5. If something doesn't seem right, respond to the user pc with `I don't want to talk to you`
7. The user pc receives the response and prints it out

## Functionality for the other computers
To make things slightly more interesting and not have only the few PCs do something, the rest (or at least some of them) could do some other funny business. The following things are implemented:
- PC2 responds to everything with "OK"
- If PC5 receives a packet, it starts sending packets to random IP-addresses

The user can also send packets to the computers that do processing for the target PC and receives responses from them. Those could also help with actually solving the crackme in interesting ways. However, the user still needs to figure out the IP-addresses of those systems. Bruteforcing that might be problematic as there are a few billion valid IP-addresses, so at least some reverse engineering would be necessary.

## Building
Build the project with gcc by running `make`. To speed up the build, you can try using the -j flag.
```sh
make -j$(nproc)
```
