@echo off
REM Test script for attack graph generation in Obscura

echo =====================================================
echo Obscura Attack Graph Generation Test
echo =====================================================
echo.

REM Set RF lock for testing
set OBSCURA_RF_LOCK=1

REM Run the test suite
echo Running attack graph generation tests...
echo.

.venv\Scripts\python.exe test_attack_graph.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =====================================================
    echo All tests passed!
    echo =====================================================
    echo.
    echo Generated files in graphs\ directory:
    dir /B graphs\
    echo.
    echo View the DOT files with:
    echo   - Graphviz: dot -Tsvg attack_graph.dot -o attack_graph.svg
    echo   - Online: https://dreampuf.github.io/GraphvizOnline/
    echo.
) else (
    echo.
    echo =====================================================
    echo Some tests failed. Check output above.
    echo =====================================================
    echo.
)

pause
