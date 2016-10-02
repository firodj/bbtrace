### Basic Block Trace: DynamoRIO client ###

This clients will record the code flow by basic block address.

How to build:
```
mkdir build
cd build

cmake -G "Visual Studio 12" -DDynamoRIO_DIR=d:\LIB\dynamorio\build\cmake ..
cmake --build . --config RelWithDebInfo
```
