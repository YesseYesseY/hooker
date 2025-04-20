test: build_dir
	cl /nologo /Fe"build/test.exe" /Fo"build/" test.cpp

build_dir:
	mkdir -p build
