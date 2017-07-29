for %%A in (C,D) do (
  echo "%%A:\DynamoRIO-6.2.0-2"
  if exist "%%A:\DynamoRIO-6.2.0-2" (
	set DYNAMORIO_HOME=%%A:\DynamoRIO-6.2.0-2
  )
)
set PATH=%DYNAMORIO_HOME%\lib32\debug;%PATH%
