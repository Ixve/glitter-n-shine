## glitter&shine

An automatic global-metadata.dat dumper for EFT

Glitter -> Injector<br>
Shine -> Payload

## how does this work?
Simple.

Glitter:
1. Uses the registry to locate the BSG Launcher installation folder
2. Launches BSGLauncher.exe with the CREATE_SUSPENDED flag
3. Drops the Shine payload into %TEMP% (shine_<procid>.dll)
4. Injects Shine into BSGLauncher.exe via LoadLibraryW

Shine:
1. Hooks "EncryptMessage" in secur32.dll (or fallback sspicli.dll)
2. Waits on the "launcher/game/start" endpoint
3. Blocks the request from going out (to prevent game from even launching)
4. Replays the request
5. Decrypts the response and parses the session key returned by the server
6. Uses the session key to send a request to "/client/metadata"
7. Decrypts the "global-metadata.dat" header to parse its version, request key and any raw subkeys
8. Decrypts the metadata using the header properties and raw keys
9. Re-writes the metadata sections to their appropriate locations and corrects the re-ordered type definitions
10. Writes the fully decrypted "global-metadata.dat" to the location of the Glitter exe

## "it's not working for me"
your account endpoint might not be the same "gw-pvp.escapefromtarkov.com", use fiddler and do it manually<br>
if you cannot comprehend a text-based tutorial on UC, here's a video: https://www.youtube.com/watch?v=jIMAjZV7v14 <br>
tools used: [Fiddler Classic](https://www.telerik.com/download/fiddler) , [Tarkov IL2CPP Decryption Thread](https://www.unknowncheats.me/forum/escape-from-tarkov/726047-tarkov-il2cpp-decryption.html) , [CPP2IL](https://github.com/SamboyCoding/Cpp2IL)

## credits
"Beakers" for the actual IL2CPP decryption, which you can find on UC [here](https://www.unknowncheats.me/forum/escape-from-tarkov/726047-tarkov-il2cpp-decryption.html)
