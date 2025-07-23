# Project Name

End-to-End Encrypted chat using Signal Protocol

## Features

Simulate a simple chat application using end-to-end encryption with Key management and decryptiong handling using machanisms like X3DH, Double Ratchet

## Usage

- /register \<username> \<password> for registering when new
- /login \<username> \<password> for logging in when existed
- /session \<username>  for establishing cipher session with some user
- /msg \<username> \<password> for sending the message (can only be done after establishing session or not the first message)
- /quit for exiting the chat (do not use Ctrl-C)

## Reference

[Open Whisper System Signal Protocol in Java](https://github.com/signalapp/libsignal-protocol-java)