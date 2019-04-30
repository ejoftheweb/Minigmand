# Minigmand
Minigmand is an implementation of Minigma for the Android platform. It replaces the BouncyCastle packages with the equivalent 
SpongyCastle ones (because of a naming conflict in Android). And some other tweaks to make it work, such as using Android's own
Base64 implementation for encoding/decoding.

To use it, just put this in the repositories section of your gradle.build file:
maven { url "https://jitpack.io" }
and in dependencies:
 implementation 'com.github.ejoftheweb:minigmand:master-SNAPSHOT'
 
 BUT: it is very much early dev code, it is certainly not production-ready. Feedback would of course be welcome.
 
 Usage.
 
 to create a key-pair(a lockset): LockSmith.createLockSet(File keyDirectory, //where the generated secret Key is to be stored
                                               LockStore lockStore, //where the public Lock will be stored
                                               String username, //the username/email associated with the lockset
                                               char[] passPhrase, //the passphrase with which the generated private Key will be encrypted
                                               int algorithm)//use Algorithms.RSA
                                               
 The LockStore can be either a MinigmaLockStore, which is PGPublic Key Ring Collection implementation, stored as a base64 text file
on the local filesystem, or an HKPLockStore, which is an http: interface to a public keyserver.

   
