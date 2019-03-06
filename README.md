# Basic Block Trace: DynamoRIO client #

This clients will record the code flow by basic block address.

## How to build:

If you have Visual Studio 15 (2017), open the **x86 Native Tools Command Prompt**.
Set the environment variable `DYNAMORIO_HOME` into dynamorio 
(eg. `C:\Workspace\dynamorio\exports`).

See `build.cmd` to create `build` dir and prepare `cmake`.

```
build
```

Then see `make.cmd` to run compile.

```
make
```

Or

```
make bbtrace
make parselog
```

## How to test:

See `test.cmd`:

```
test
```

## How to run:

See `run.cmd`, to run instrumentation for example:

```
run bbtrace -- %windir%\system32\calc.exe
```

By default the CONFIG is `relase` or called **RelWithDebInfo**, so the output will be at
`bin\RelWithDebInfo` including the bbtrace trace output which is placed on same directory as
the client dll.

The trace file will have name `bbtrace.dll.calc.exe.yyyymmdd-hhiiss.ext` with the ext:
* txt -> info or stdout
* log
* number -> id with per thread trace