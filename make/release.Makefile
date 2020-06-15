ifndef MK_RELEASE
MK_RELEASE=1

include make/ci.Makefile

build: clean
	poetry build

publish: build
	poetry publish

endif
