test: build_dir
	cl /Zi /Fd"build/test.pdb" /nologo /Fe"build/test.exe" /Fo"build/" test.cpp user32.lib

build_dir:
	mkdir -p build
