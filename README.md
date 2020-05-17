# Basic Block Trace: DynamoRIO client #

This clients will record the code flow by basic block address.

## How to build:

If you have Visual Studio 15 (2017), open the **x86 Native Tools Command Prompt**.
Set the environment variable `DYNAMORIO_HOME` into dynamorio
(eg. `C:\Workspace\dynamorio\exports`).

See `build.cmd` to create `build` dir and prepare `cmake`.

```
> build
```

Then see `make.cmd` to run compile.

```
> make
```

Or

```
> make bbtrace
> make parselog
> make grapher
```

## How to test:

See `test.cmd`:

```
> test
```

## How to run:

See `run.cmd`, to run instrumentation for example:

```
> run bbtrace -- %windir%\system32\calc.exe
```

By default the CONFIG is `relase` or called **RelWithDebInfo**, so the output will be at
`bin\RelWithDebInfo` including the bbtrace trace output which is placed on same directory as
the client dll.

The trace file will have name `bbtrace.dll.calc.exe.yyyymmdd-hhiiss.ext` with the ext:
* txt -> info or log
* bin -> main thread trace
* bin.%id% -> per thread trace

## How to parse log:

If the executable name `calc.exe` then:

```
> run parselog -j bin\RelWithDebInfo\bbtrace.dll.calc.exe.yyyymmdd-hhiiss.bin`
```

Option *-j* to enable multithread. The parselog actually doing nothing.

If you want to dump the list of basic block executed use `grapher`

```
> run grapher -j bin\RelWithDebInfo\bbtrace.dll.calc.exe.yyyymmdd-hhiiss.bin`
```

The output csv will be: bin\RelWithDebInfo\bbtrace.dll.calc.exe.yyyymmdd-hhiiss.csv

## Convention

Refer to (Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html), here a brief and some modification:

1. Use `#pargma once` guard.
2. Use C++-style casts like `static_cast<float>(double_value)`.
3. File names is lowercase w/ underscore: `logrunner`, `log_runner`.
4. Types names for `struct`, `class`, `enum`, `typedef`, and `using` is camelcase eg. `MyExcitingClass`.
5. Variable names, function parameters, data member: lowercase with underscore eg. `a_local_variable`.
6. Data members of classes (but not structs) additionally have trailing underscores eg. `a_class_data_member_`
7. Global variable exported or static prefixed with `g_`
8. const and enum value: camelcase prefix "k" eg. `kDaysInAWeek`, `kNone`.
9. getter/setter: same as member without underscore suffix, setter: prefix with `set_`. eg. `set_table_name(T v)`, `table_name()`.
10. Funtion or method name: camelcase `AddTableEntry` preferable prefix with a verb.
11. Avoid namespaces.
12. Macros: `FULL_UPPERCASE`
13. Indent with 2 spaces.