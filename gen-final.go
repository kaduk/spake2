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
	Ka := hashTT[16:30]
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
	TTServerClient := "06000000000000007365727665720600000000000000636c69656e744100000"+
	"0000000000498156fb8a640f7b4d656d5c38e1f69fc9db9aefa2537a92462172ed4dc1"+
	"97fea356b628fcbc93df133b6c54317e0e805eaa71cb1a23cc2ffc287247c836855ab4"+
	"100000000000000040ccd1b742844109eafa973972bef13844124e56163c225e529ec7"+
	"76ebaf1fb1142e1dc4d792c1762998290e45a8419a8059aa45004d9ae099dada77736b"+
	"cd65f410000000000000004e896fa87681d37fe9c3e68e9fa406265e63dd0b1b812c80"+
	"2b0bba8557e5bcfb90d7ca84d3d09eea0fe84ff6e12b161f282a0393c2f94d5b6a6230"+
	"e115e0e7ce0200000000000000019eed1f4855a0b7e22096a04936c217a5f0cfe480ae"+
	"626b9d4427dce9373b3f3";

	TTServerClientData, err := hex.DecodeString(TTServerClient)
	if err != nil {
		log.Fatal("error decoding hex")
	}
	complete("server", "client", TTServerClientData)
	fmt.Printf("\n\n")

	TTClient := "00000000000000000600000000000000636c69656e74410000000000000004350422b3f16b4a030defd0a9b689bb2454a2a24974889583d9c47653ac5bbef5a0d33c8284aec0d4906d8ea22de211d4a60c8e0d6dd3c4d21114a059a7e4c753410000000000000004321f59e8ae418a913005a860779a1e2c567715325a91ec75f6625a6dca7a7b25ddb61333c6f42c9ade343dfdc21cfc88c97edf7a56c2d9d2e309d33542e8f04d410000000000000004105ff327fcdb0bdd576f894bc2789b88b39ea6b24fd06062defeb7de369ddf8555d1e957ef2e314780edc92ff8827f89248a16941265f21752cd9330526b86b720000000000000001af09ee09d36e14781d6af24e17eb927141148dab79d749f6a15a37cbcaebb49"
	TTClientData, err := hex.DecodeString(TTClient)
	if err != nil {
		log.Fatal("error decoding hex client")
	}
	complete("", "client", TTClientData)
	fmt.Printf("\n\n")
	
	TTServer := "06000000000000007365727665720000000000000000410000000000000004d646aa145fee782fb65115b98265833503bd3acd8ce825f9655c51f89cd7f183935be0c56300e27522411211814085d2e72ffaa2b7dd8b3fe8bd2a679505c538410000000000000004e6c8df6777bcf56a7a5a1dd25a9b2aafeb7bd04460c7a6c27d030f021c146da575116155217d99157398c9a281d459d5d5742767ff079e1f7b1466f83afb8f8f4100000000000000043e6f809c51415045d96135997c3b2b8aa203152134b24351dcc34638e3998a9313d63aa398730bda790bd9494d51aa5cfc7a2a504d87b553d639894d2e485dbe20000000000000002a7ae95677292de1b1c3e073d4f446cafc49686a1ac15be4c4a7f7ff68be7eb4"
	TTServerData, err := hex.DecodeString(TTServer)
	if err != nil {
		log.Fatal("error decoding hex server")
	}
	complete("server", "", TTServerData)
	fmt.Printf("\n\n")

	TTEmpty := "00000000000000000000000000000000410000000000000004842fb511920771b8bb5598cf86c039c656d96bf17fcc0ce782a8766d2c3809b6cca257d6892273dd9598b2b02cc807a82a23f57adf20fd86cffc2de5a6b424af410000000000000004dfbe6ee311032dd0afcaa64dc9c2f0c0f0731faaa347f41d9ab9473ad57028bd6adb4276e893971fe9ed07eddf9ee2fd9b5ba50b4ff38832832b05f054acddc8410000000000000004ff5129244237f0b2d9f365bfee3d5af1d39eee85cfbe50b6f03fd2c6fc5fef4d039a2c29e686f2d0707fb29c88986f0d1e31f8b320f723fe2fef4e5681f20370200000000000000094b84fe32e2a40b3cacaaf0654f315f4b59b327fe7a5f2377e4c8eeaf704bb22"
	TTEmptyData, err := hex.DecodeString(TTEmpty)
	if err != nil {
		log.Fatal("error decoding hex server")
	}
	complete("", "", TTEmptyData)
	

}

