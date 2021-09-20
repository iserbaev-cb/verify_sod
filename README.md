# verify_sod

Example:

`sh chmod +x csca_toks.sh && /csca_toKs.sh ...`


## you need proper version of openssl

### to install it run

`brew install rbenv/tap/openssl@1.0`

`export LDFLAGS="-L/usr/local/opt/openssl@1.0/lib"`
`export CPPFLAGS="-I/usr/local/opt/openssl@1.0/include"`
`CONFIGURE_OPTS="--with-openssl-dir=$(brew --prefix openssl@1.0)" RUBY_CONFIGURE_OPTS="--with-openssl-dir=$(brew --prefix openssl@1.0)" rbenv install 2.3.8`
`echo 'export PATH="/usr/local/opt/openssl@1.0/bin:$PATH"' >> ~/.zshrc`
`source ~/.zshrc`
`openssl version`