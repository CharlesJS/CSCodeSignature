# CSCodeSignature

Does your app need to deal with code signatures?
Are you sick of the ugly CoreFoundation interface for dealing with them?
Then fret no more; `CSCodeSignature` is a nice Swifty wrapper around the macOS code signing framework.
Just pass it a `URL` to a file in the file system, and `CSCodeSignature` will tell you whether it is signed or not, as well as provide a bunch of information about the signature.

This library is free for any use under the terms of the MIT license.

Charles Srstka

