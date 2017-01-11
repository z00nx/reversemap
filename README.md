# reversemap
Analyse SQL injection attempts in web server logs

The program can either be run in batch mode or interactive mode.
In batch mode the program will accept Apache web server logs and will deobfuscate requested URLs from the logs.
In interactive mode the program will prompt for user input and will print the deobfuscated results.

The program can deobfuscate the following obfuscation techniques:
* SQL CHAR encoding
* SQL CAST encoding
* Case encoding of SQL keywords
* Substring(Disabled as it will fail with nested queries)

Pull requests, patches and feedback is welcome.
