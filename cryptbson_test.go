//
// packager cryptbson package
// Author: Guido Ronchetti <guido.ronchetti@nexo.cloud>
// v1.0 20/08/2017
//

package cryptbson

import (
	"crypto/rand"
	"fmt"
	"os"
	"reflect"
	"testing"
	// third parties
	"golang.org/x/crypto/nacl/box"
)

var (
	collector *Collector = nil
	agent     *Agent     = nil
)

func TestMain(m *testing.M) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Unable to generate keys: %s.\n", err.Error())
		os.Exit(1)
	}
	collector, err = NewCollector(*privateKey, *publicKey)
	if err != nil {
		fmt.Printf("Unable to create collector: %s.\n", err.Error())
		os.Exit(1)
	}
	agent, err = NewAgent(collector.PublicKey())
	if err != nil {
		fmt.Printf("Unable to create agent: %s.", err.Error())
		os.Exit(1)
	}
	err = collector.PrecomputeForAgent("agent1", agent.PublicKey())
	if err != nil {
		fmt.Printf("Unable to precompute agent: %s.", err.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type fakeData struct {
	Title   string
	Message string
}

func TestBox(t *testing.T) {

	fm := fakeData{
		Title:   "Test message",
		Message: "This is a fake critical message.",
	}
	ciphered, err := Box(agent.SharedKey(), fm)
	if err != nil {
		t.Fatalf("Unable to box: %s.", err.Error())
	}

	var result fakeData
	cshared, ok := collector.SharedKey("agent1")
	if !ok {
		t.Fatalf("Unable to find shared key.")
	}
	err = Unbox(ciphered, cshared, &result)
	if err != nil {
		t.Fatalf("Unable to unbox item: %s.", err.Error())
	}

	if reflect.DeepEqual(result, fm) != true {
		t.Fatalf("Wrong comparison: %#v != %#v.", result, fm)
	}

}
