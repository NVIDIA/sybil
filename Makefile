debug:
	cargo build

release:
	cargo build --release

deb:
	cargo deb

rpm: release
	cargo generate-rpm

clean:
	cargo clean
