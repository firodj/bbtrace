# Basic Block Trace: DynamoRIO client #

This clients will record the code flow by basic block address.

## How to build:

```
mkdir build
cd build

cmake -G "Visual Studio 12" -DDynamoRIO_DIR=d:\LIB\dynamorio\build\cmake ..
cmake --build . --config RelWithDebInfo
```

## How to test:

```
drrun.exe -c test_bbtrace.dll -- test_app.exe > ..\tests\test_bbtrace.expect 2>&1
```

## How to build only **bbtrace_flow**:

```
cmake --build . --config Debug --target bbtrace_flow
```