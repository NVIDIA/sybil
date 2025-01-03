export SLURM_VERSION ?= 24.11

check:
	cargo clippy --all-features

debug:
	cargo build
	[ "$$WITH_SLURM" = "1" ] && cargo rustc --lib --crate-type=cdylib --features slurm ||:

release:
	cargo build --release
	[ "$$WITH_SLURM" = "1" ] && cargo rustc --release --lib --crate-type=cdylib --features slurm ||:

deb: export WITH_SLURM := 1
deb: release
	cargo deb --no-build

rpm: export WITH_SLURM := 1
rpm: release
	cargo generate-rpm

clean:
	cargo clean
