# Secure Streaming Service
This repo serves as a demo for a secure streaming service that has the option to use between 3 different cipher modes: AES/GCM, ChaCha20-Poly1305 and a OTP-PRG mode.
## Architecture Layout
This demo works with a client and proxy java programms that first establish via a handshake(with TCP socket) which cipher mode will be used and which address (host:port) to
send datagram packets to. Once established the sessian details, the TCP socket is terminated and the service starts sending datagrams(via UDP socket) to the requested proxy
address, encrypting each packet with the agreeed cipher mode. Upon recieving it, the proxy service will decrypt each packet and forward it to the remote address of the media 
application responsible for playing the video(e.g. VLC media player).
## Config.properties
A config.properties file is used to establish some properties for both the server and proxy.\
```
//Server
handshakePort=7000 //Port for server to await establishing handshake and session details
keystoreFile=server_keystore.p12 //Server keystore file for its private key
keystorePassword=PASSWORD //Server keystore password. For pratical purposes outside of this demo, the password should not be in plaintext in any file
keyAlias=streamserver //Private key alias
keyPassword=PASSWORD //Private key password for retrieval. Same note for keystorePassword applies here :)
//Client
cipher=AES_GCM //The cipher mode to be used
serverHost=127.0.0.1 //The server host to contact
serverCertificateFile=server_cert.pem //The server certificate file containing the public key
handshakePort=7000 //The server handshake port
remote=127.0.0.1:5000 //The remo address for the proxy
localdelivery=127.0.0.1:6000 //The address to forward decripted packets to(e.g. VLC media player)
```
## Compile and Run
To compile and run this demo:
### Compile
```javac server/*.java client/*.java utils/*.java crypto/*.java```
### Run Server
```java server/StreamServer.java server/movies/<movie.dat>```
Where <movie.dat> can be cars.dat(Cars 2 trailer) or monsters.dat(Monsters University trailer)
### Run Client
```java client/UdpProxy.java```
### VLC Media Player
To view the movie stream in VLC, open network in VLC at ```udp://@:6000```
