export SLURM_VERSION ?= 24.11
export TARGET ?= $(shell rustc -vV | awk '/host/{print $$2}')

check:
	cargo clippy --all-features

debug:
	cargo build --target $(TARGET)
ifdef WITH_SLURM
	cargo rustc --target $(TARGET) --lib --crate-type=cdylib --features slurm
endif

release:
	cargo build --target $(TARGET) --release
ifdef WITH_SLURM
	cargo rustc --target $(TARGET) --release --lib --crate-type=cdylib --features slurm
endif

deb: release
	cargo deb --target $(TARGET) --no-build --multiarch foreign
ifdef WITH_SLURM
	cargo deb --target $(TARGET) --no-build --multiarch foreign --variant spank
endif

rpm: release
	cargo generate-rpm --target $(TARGET)
ifdef WITH_SLURM
	cargo generate-rpm --target $(TARGET) --variant spank
endif

clean:
	cargo clean
