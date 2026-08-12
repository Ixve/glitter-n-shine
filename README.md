## glitter&shine

An automatic global-metadata.dat dumper for EFT

Glitter -> Injector<br>
Shine -> Payload

## how does this work?
Simple.

Glitter:
1. Prompts to use the Steam (Using a steam://run/appid URI) or direct BSG launcher installation (which will use the Registry to find the installation folder)
2. Prompts the folder to output the final files into
3. Kills EscapeFromTarkov.exe and BSGLauncher.exe to prevent issues
4. Starts the launcher via previously selected technique
5. Drops Shine into %TEMP%
6. Injects it into BSGLauncher.exe

Shine:
1. Allocates a console in the launcher
2. Redirects STDOUT to NUL to prevent the launchers log spam (albeit I do not care about the CEF error spam as it is minor)
3. Hooks EncryptMessage within secur32.dll (or fallback sspicli.dll)
4. Captures the Bearer token, PHPSESSID, User-Agent and launcher version
5. Gets the latest EFT version from /launcher/game-updates/eft
6. Resolves the CDN endpoint from /launcher/game-installation/eft
7. Gets the ConsistencyInfo manifest
8. Checks the output folder for the following files to see if they're up to date or if they exist: "GameAssembly.dll", "UnityPlayer.dll", "EscapeFromTarkov.exe", "globalgamemanagers", "global-metadata.dat"
9. Downloads whatever files are necessary, or replaces them if they're outdated, corrupted, etc (As they are needed for IL2CPPDumper/CPP2IL generation)
10. Calls IGameBackendService.GetGameSessionAsync in memory (due to the HWID logging etc that it sends)
11. Uses the session key to send a request to /client/metadata
12. Decrypts the global-metadata.dat header to parse the version, request keys and any raw subkeys
13. Decrypts the metadata using the header properties and raw keys
14. Re-writes the metadata sections to their appropriate locations and corrects the re-ordered type definitions
15. Writes the fully decrypted global-metadata.dat to the provided output folder location, alongside the rest of the files

## "it's not working for me"
your account endpoint might not be the same "gw-pvp.escapefromtarkov.com", use fiddler and do it manually<br>
if you cannot comprehend a text-based tutorial on UC, here's a video: https://www.youtube.com/watch?v=jIMAjZV7v14 <br>
tools used: [Fiddler Classic](https://www.telerik.com/download/fiddler) , [Tarkov IL2CPP Decryption Thread](https://www.unknowncheats.me/forum/escape-from-tarkov/726047-tarkov-il2cpp-decryption.html) , [CPP2IL](https://github.com/SamboyCoding/Cpp2IL)

## credits
"Beakers" for the actual IL2CPP decryption, which you can find on UC [here](https://www.unknowncheats.me/forum/escape-from-tarkov/726047-tarkov-il2cpp-decryption.html)<br>
AI for writing the code because i'm too lazy to write all this shit in C++ , i'd rather stick to being an angelscript/enma warrior. s/o pcx my beloved.
