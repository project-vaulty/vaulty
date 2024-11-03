CURRENT_PATH=$PWD

cd ../source/vault
cargo build --release
cp target/release/vaulty $CURRENT_PATH/vaulty

cd ../cli
cargo build --release
cp target/release/vaulty-cli $CURRENT_PATH/vaulty-cli