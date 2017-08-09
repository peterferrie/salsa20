msvc:
		cl /nologo /O2 /Ot /DTEST test.c s20.c
gnu:
		gcc -DTEST -Wall -O2 test.c s20.c -otest	 
clang:
		clang -DTEST -Wall -O2 test.c s20.c -otest	    