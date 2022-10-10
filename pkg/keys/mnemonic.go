package keys

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lizc2003/gotron-sdk/pkg/keys/hd"
	"github.com/tyler-smith/go-bip39"
)

// FromMnemonicSeedAndPassphrase derive form mnemonic and passphrase at index
func FromMnemonicSeedAndPassphrase(mnemonic, passphrase string, index int) (*btcec.PrivateKey, *secp256k1.PublicKey) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, ch := hd.ComputeMastersFromSeed(seed, []byte("Bitcoin seed"))
	private, _ := hd.DerivePrivateKeyForPath(
		btcec.S256(),
		master,
		ch,
		fmt.Sprintf("44'/195'/0'/0/%d", index),
	)

	return btcec.PrivKeyFromBytes(private[:])
}
