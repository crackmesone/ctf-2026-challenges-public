package main

import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket" 
import "encoding/binary"
import "crypto/aes"
import "crypto/cipher"

import (
	"io"
	"fmt"
	"log"
	"net/http"
	"bytes"
)

func main() {
	fmt.Println("Starting server...")
	go httpInit()

	http.HandleFunc("/", handler)

	fmt.Println("Server is running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		io.WriteString(w, "Nothing to see here :{")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func httpInit() {
	if handle, err := pcap.OpenLive("re0", 1600, true, pcap.BlockForever); err != nil {
  		panic(err)
	} else if err := handle.SetBPFFilter("icmp"); err != nil {  // optional
  		panic(err)
	} else {
  		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  		for packet := range packetSource.Packets() {
			d := packet.Data()
			p := d[0x14:0x18] //0x01 protocol
			//t := d[0x22:0x23] // 0x08 icmp type
			c := d[0x24:0x26] //icmp checksum
			i := d[0x26:0x28] //icmp id
			ts := d[0x2a:0x2e] //icmp timestamp
			tsb := binary.LittleEndian.Uint32(ts)
			ta, tb := uint16(tsb>>16), uint16(tsb)
			cs := binary.LittleEndian.Uint16((c))
			xa := ta ^ cs
			xb := tb ^ cs
			a := make([]byte, 2)
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(a, xa)
			binary.BigEndian.PutUint16(b, xb)
			k := append(a, p...)
			k2 := append(k, c...)
			k3 := append(k2, ts...)
			k4 := append(k3, i...)
			k5 :=	append(k4, b...)
			mi := binary.LittleEndian.Uint16(i)
			if mi == 0x1337  {
				s := binary.BigEndian.Uint16(d[0x10:0x12])
				if s == 0x20 {
					mt := binary.LittleEndian.Uint32(ts)
					if mt == 0xe55fdec6 {
						if d[0x22]  ==0x8 {
							//pt := []byte("CMO{fUn_w1th_m4g1c_p4ck3t5}")
							ct := []byte{81, 241, 165, 41, 180, 223, 126, 192, 42, 59, 47, 143, 36, 61, 78, 179, 90, 237, 176, 207, 11, 156, 221, 140, 205, 230, 14, 155, 62, 196, 100, 12}
							ci, _ := aes.NewCipher(k5)
							
							//Aes decrypt
							pt := make([]byte, len(ct))
							stream := cipher.NewCBCDecrypter(ci, k5)
							stream.CryptBlocks(pt, ct)

							//Aes encrypt
							//bPt := PKCS5Padding([]byte(pt), aes.BlockSize, len(pt))
							//ct := make([]byte, len(bPt))
							//stream := cipher.NewCBCEncrypter(ci, k5)
							//stream.CryptBlocks(ct, bPt)

							//fmt.Printf("key %x\n",k5)
							//fmt.Printf("ct: %x", ct)
							//fmt.Println()
							//fmt.Println("string ct: ", string(ct))
							//fmt.Println("pt: ", pt)
							fmt.Println(string(pt))
						}
					}	
				}
			}
  		}
	}
}
