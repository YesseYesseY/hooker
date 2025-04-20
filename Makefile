test: build_dir
	cl /nologo /Fe"build/test.exe" /Fo"build/" test.cpp user32.lib

build_dir:
	mkdir -p build
