@echo off
REM Test script runner for Windows

if "%1"=="" (
    echo Usage: run_test.bat ^<domain^>
    echo Example: run_test.bat example.com
    exit /b 1
)

echo.
echo ========================================
echo  Backend Data Test Script
echo ========================================
echo.
echo Testing domain: %1
echo.

python test_backend_data.py %1

echo.
echo ========================================
echo  Test Complete
echo ========================================
echo.
echo Check the output above to see:
echo  - Which phases have data
echo  - Which keys are missing
echo  - Data completeness percentage
echo.
echo A JSON export file has been created with all raw data.
echo.
pause
