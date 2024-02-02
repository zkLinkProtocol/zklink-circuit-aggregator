
lint:
	typos --write-changes
	cargo fmt
	cargo clippy --all --fix --allow-dirty --allow-staged --all-targets --all-features -- -D warnings
	cargo sort
	cargo machete

lint-check:
	cargo fmt -- --check
	cargo clippy
	cargo sort --check
	cargo machete

build:
	cargo build

fix:
	cargo fix --allow-dirty --allow-staged

#test:
#	cargo test -p final_aggregation

fmt:
	cargo fmt

tool:
	#cargo install sqlx-cli --version 0.6.3
	cargo install taplo-cli --locked
	cargo install cargo-sort cargo-machete
	#https://github.com/crate-ci/typos
	cargo install typos-cli
	#https://github.com/est31/cargo-udeps
	cargo install cargo-udeps --locked



