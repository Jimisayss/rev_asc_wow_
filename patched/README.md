# Static Patch (Ascension_unlocked.exe)

This directory was intended to hold a statically patched version of `Ascension.exe`.

However, the final solution was implemented as a dynamic, runtime injector (`scripts/injector.py`). This approach was chosen because it is more robust, does not require modifying the original game files, and was achievable within the constraints of the development environment.

Therefore, no `Ascension_unlocked.exe` is provided. The unlock is performed in memory by running the main injector script while the game is running.
