//
// packager cryptbson package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 20/08/2017
//

// Package cryptbson implements a middleware layer to
// implement application level encryption for the bson
// encoding format.
package cryptbson

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	// third parties
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/mgo.v2/bson"
)

const (
	cTagLabel  = "encrypt"
	cNonceSize = 24
)

type Agent struct {
	// in memory shared key
	sharedKey *[32]byte
	// random generated self identifying keys
	publicKey *[32]byte
	// mutex
	mtx sync.RWMutex
}

func NewAgent(recipientPublicKey [32]byte) (*Agent, error) {
	senderPublicKey, senderPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to produce sender key-pair: %s",
			err.Error(),
		)
	}
	ag := &Agent{
		publicKey: senderPublicKey,
		sharedKey: new([32]byte),
	}
	box.Precompute(ag.sharedKey, &recipientPublicKey, senderPrivateKey)
	return ag, nil
}

func (a *Agent) PublicKey() [32]byte {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	return *a.publicKey
}

func (a *Agent) SharedKey() [32]byte {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	return *a.sharedKey
}

func Box(sharedKey [32]byte, v interface{}) ([]byte, error) {
	plain, err := bson.Marshal(v)
	if err != nil {
		return nil, err
	}
	// encrypt
	var nonce [cNonceSize]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	ciphered := box.SealAfterPrecomputation(nonce[:], plain, &nonce, &sharedKey)
	return ciphered, nil
}

func Unbox(data []byte, sharedKey [32]byte, v interface{}) error {
	if len(data) < cNonceSize {
		return fmt.Errorf(
			"encrypted data too short should be at least %d bytes long",
			cNonceSize,
		)
	}
	var nonce [cNonceSize]byte
	copy(nonce[:], data[:cNonceSize])

	plain, ok := box.OpenAfterPrecomputation(nil, data[cNonceSize:], &nonce, &sharedKey)
	if !ok {
		return fmt.Errorf(
			"unable to unbox the ciphered message",
		)
	}
	err := bson.Unmarshal(plain, v)
	if err != nil {
		return err
	}
	return nil
}

type Collector struct {
	publicKey  *[32]byte
	privateKey *[32]byte
	// in memory shared key
	sharedKeys map[string]*[32]byte
	// mutex
	mtx sync.RWMutex
}

func NewCollector(privateKey, publicKey [32]byte) (*Collector, error) {
	return &Collector{
		privateKey: &privateKey,
		publicKey:  &publicKey,
		sharedKeys: make(map[string]*[32]byte),
	}, nil
}

func (c *Collector) PublicKey() [32]byte {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return *c.publicKey
}

func (c *Collector) SharedKey(agent string) ([32]byte, bool) {
	value, ok := c.sharedKeys[agent]
	if !ok {
		return [32]byte{}, false
	}
	return *value, true
}

func (c *Collector) PrecomputeForAgent(agent string, senderPublicKey [32]byte) error {
	sharedKey := new([32]byte)
	// read and precompute
	c.mtx.RLock()
	box.Precompute(sharedKey, &senderPublicKey, c.privateKey)
	c.mtx.RUnlock()
	// update shared keys map inside the struct
	c.mtx.Lock()
	c.sharedKeys[agent] = sharedKey
	c.mtx.Unlock()

	return nil
}
