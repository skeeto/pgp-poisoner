# PGP Key Poisoner

This tool poisons PGP keys by attaching thousands, or more, valid but
useless signatures. When these signatures are uploaded to a keyserver,
the [targeted key becomes unusable][info]. The current, popular OpenPGP
implementations are not robust against such attacks.

## Usage

All inputs must be in binary form, not ASCII-armored. All outputs are
also in binary form. The target key is fed to standard input, and the
poisoned form is written to standard output. Only the first user ID on
the input is poisoned.

```
usage: pgp-poisoner [-k FILE] [-n INT] <target.pgp >poisoned.pgp
  -h         print this help message
  -k FILE    signing secret keys output file [keys.pgp]
  -n INT     number of signatures to append [65536]
```

Each signature is valid, and all of the signing secret keys are saved to
`keys.pgp` (configured via `-k`). In addition to the poisoned key, these
keys could also be uploaded to keyservers to further harden the attack.
The keys and signatures are given various random creation dates and
names so that they cannot easily be filtered out.

The tool generates around 6,500 new signatures per second, so you can
create a million junk signatures in just a few minutes.

### Poisoning a test key

Want to see what a poisoned key looks like when imported to GnuPG? This
will attach 200,000 junk signatures to a locally-generated key. I chose
rsa4096, but the kind of key doesn't actually matter.

    $ mkdir gen
    $ gpg --homedir gen --batch --passphrase '' --quick-gen-key foo rsa4096
    $ gpg --homedir gen --export >clean.pgp
    $ pgp-poisoner -n200000 <clean.pgp >poison.pgp

After a few seconds you will now have two outputs: the poisoned key,
`poison.pgp` (23MB), and all the secret keys used to create the
signatures, `keys.pgp` (40MB). Try importing the poisoned key onto a
temporary keyring:

    $ mkdir tmp
    $ gpg --homedir tmp --import poison.pgp

As of GnuPG 2.2.17, this last command will lock up for about 15 minutes,
then ultimately fail to import the key after printing bogus information
about it. Trying to `--recv-key` this key from a keyserver would have
similar results, making the key unusable.

## Why?

First and foremost, this tool creates configurable test inputs for
OpenPGP implementations. My initial motivation was observing how various
implementations handle these inputs.

Further, this attack has been known for years, and in 2019 it's been
used against real keys on keyservers. This tool is nothing new and does
not create any new capabilities. It's merely proof that such attacks are
*very* easy to pull off. **It doesn't take a nation-state actor to break
the PGP ecosystem, just one person and couple evenings studying RFC
4880**. This system is not robust.

As far as keyserver weaknesses go, key poisoning attacks are really just
scratching the surface. For example, did you know other people can bind
your subkeys to their primary key? Even when (if?) this fire is put out,
more will likely follow.

This tool does not handle the final step of uploading the poisoned key
to a keyserver, and there are a couple minor technical challenges
involved in doing so successfully, probably beyond the reach of script
kiddies. As shown, GnuPG chokes on poisoned keys — which is why the
attack works so well — so it's not just a simple matter of importing the
poisoned key and using `--send-keys.` I'm not interested in actually
doing this step, so I will not solve these issues.


[info]: https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f

