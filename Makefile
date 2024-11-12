.PHONY: default install
default:
	(test -d build || ./configure)
	(cd build && make)

install:
	(cd build && make install)


