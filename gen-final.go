package main

import (
	"fmt"
	"log"
	"encoding/hex"
	"crypto/hmac"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

func complete(A string, B string, TT []byte) {
	fmt.Printf("A: %s, B: %s\n", A, B)
	h := sha256.New()
	h.Write(TT)
	hashTT := h.Sum(nil)
	fmt.Printf("Hash(TT) = 0x%x", hashTT)
	Ke := hashTT[:16]
	Ka := hashTT[16:]
	fmt.Printf("Ke = 0x%x\n", Ke)
	fmt.Printf("Ka = 0x%x\n", Ka)
	confirmer := hkdf.New(sha256.New, Ka, nil, []byte("ConfirmationKeys"))
	KcA := make([]byte, 16)
	KcB := make([]byte, 16)
	confirmer.Read(KcA)
	confirmer.Read(KcB)
	fmt.Printf("KcA = 0x%x\n", KcA)
	fmt.Printf("KcB = 0x%x\n", KcB)
	hmacA := hmac.New(sha256.New, KcA)
	hmacB := hmac.New(sha256.New, KcB)
	hmacA.Write(TT)
	hmacB.Write(TT)
	fmt.Printf("A conf = 0x%x\n", hmacA.Sum(nil))
	fmt.Printf("B conf = 0x%x\n", hmacB.Sum(nil))
}

func main() {
	TTServerClient := "06000000000000007365727665720600000000000000636c69656e74410000000000000004a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c41000000000000000406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b741000000000000000412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d332520000000000000002ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f"

	TTServerClientData, err := hex.DecodeString(TTServerClient)
	if err != nil {
		log.Fatal("error decoding hex")
	}
	complete("server", "client", TTServerClientData)
	fmt.Printf("\n\n")

	TTClient := "00000000000000000600000000000000636c69656e74410000000000000004a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a410000000000000004e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc4100000000000000048f83ec9f6e4f87cc6f9dc740bdc2769725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cff5361f7e819e53d8d3c3a2922e0d837aa620000000000000000548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae"
	TTClientData, err := hex.DecodeString(TTClient)
	if err != nil {
		log.Fatal("error decoding hex client")
	}
	complete("", "client", TTClientData)
	fmt.Printf("\n\n")
	
	TTServer := "06000000000000007365727665720000000000000000410000000000000004f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b04100000000000000040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db41000000000000000445ee233b8ecb51ebd6e7da3f307e88a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9b844bb3e8dd9554aafc5b53813504c1cbe2000000000000000626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254"
	TTServerData, err := hex.DecodeString(TTServer)
	if err != nil {
		log.Fatal("error decoding hex server")
	}
	complete("server", "", TTServerData)
	fmt.Printf("\n\n")

	TTEmpty := "00000000000000000000000000000000410000000000000004a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66410000000000000004589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d4100000000000000041a3c03d51b452537ca2a1fea6110353c6d5ed483c4f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee97986ce3d1438e13554377220000000000000007bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca"
	TTEmptyData, err := hex.DecodeString(TTEmpty)
	if err != nil {
		log.Fatal("error decoding hex server")
	}
	complete("", "", TTEmptyData)
	

}

