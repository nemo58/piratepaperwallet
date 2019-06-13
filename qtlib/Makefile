ifeq ($(shell uname),Darwin)
    EXT := dylib
else
    EXT := a
endif

all: target/debug/arrrpaperrust.$(EXT)
	g++ src/main.cpp -L./target/debug -lzecpaperrust -lpthread -ldl -o run
	./run

target/debug/arrrpaperrust.$(EXT): src/lib.rs Cargo.toml
	cargo build --lib

clean:
	rm -rf target
	rm -rf run