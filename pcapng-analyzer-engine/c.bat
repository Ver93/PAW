@echo off
setlocal enabledelayedexpansion

echo Counting lines in project...
echo.

set TOTAL=0

for /r %%f in (*.c *.h) do (
    set COUNT=0

    for /f %%x in ('findstr /R "^" "%%f" ^| find /c /v ""') do (
        set COUNT=%%x
    )

    echo %%f: !COUNT! lines
    set /a TOTAL+=COUNT
)

echo.
echo -------------------------------------
echo Total lines of code: %TOTAL%
echo -------------------------------------

endlocal
