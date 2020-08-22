#!/bin/sh

export GNUPGHOME=$(mktemp -d)
chmod 700 $GNUPGHOME  # make GnuPG happy
mkdir data

keygen(){
  echo "# the comments in this string are handled by sed (below)
  %no-protection  # passphraseless keys
  #%transient-keys  # uncomment for possibly faster key generation
  Key-Type: RSA
  Key-Length: 2048
  Subkey-Type: rsa
  Subkey-Length: 2048
  Name-Real: $1
  Name-Email: $2-openpgp-fa-mathe-sgb@mikitsu.me
  %commit  # not really sure if this is needed, but it won't hurt
  " | sed -e 's/^  //' -e 's/#.*//' | gpg --batch --generate-key
}

gpghandle(){ gpg --encrypt --sign --recipient "$1" --default-key "${2:-Key 2}" "${@:3}"; }

keygen 'Testing Key 1' testkey-1
keygen 'Testing Key 2' testkey-2
keygen 'Testing Key 3' testkey-3
echo "$0: ----- generated keys -----"
gpg --default-key 'Key 1' --batch --yes --sign-key 'Key 2'
gpg --default-key 'Key 3' --batch --yes --sign-key 'Key 2'
gpg --default-key 'Key 2' --batch --yes --sign-key 'Key 1'
echo "$0: ----- cross-signed some keys -----"
gpg --export 'Key 1' 'Key 2' > data/public-keys
gpg --export-secret-keys 'Key 1' > data/secret-keys
gpg --export-secret-keys > data/complete-key-set
echo "$0: ----- exported keys -----"
echo 'Hello there.
This is a test text.
Using text mode should handle line endings
and make me be five (plus a trailing newline) lines long even on Windows and Mac.
Bye!' \
  | gpghandle 'Key 1' 'Key 2' --textmode > data/text-message
echo 'If you can read this, I have a problem' \
  | gpghandle 'Key 2' > data/unreadable-key2-message
echo 'If you can read this, I have the same problem' \
  | gpghandle 'Key 3' > data/unreadable-key3-message
echo 'If you can read this, guess what kind of problem I have' \
  | gpghandle 'Key 2' 'Key 2' --recipient 'Key 3' > data/unreadable-key23-message
echo 'You should have no idea who signed this' \
  | gpghandle 'Key 1' 'Key 3' > data/unknown-sig-message
gpghandle 'Key 1' 'Key 2' --output data/encrypted-binary /bin/true
echo 'You AND some other key can read this' \
  | gpghandle 'Key 1' 'Key 2' --recipient 'Key 3' > data/multi-key-message
echo "$0: ----- generated some messages -----"
rm -r $GNUPGHOME

load_path=$(printf '%q:' data/*-keys)$(printf '%q:' data/*-message)
load_path="${load_path}data/encrypted-binary"
env FA_MATHE_OPENPGP_LOADPATH="$load_path" python3 -m openpgp info
echo "$0: ----- read generated files -----"
echo "$0: you should see two WARNING messages (unknown signing key)"
echo "$0: and three ERROR messages (No session key)"
