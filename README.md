# onetimepad
This program takes a key string and a message string. The client sends both to a daemon that encrypts the message with the key and returns that encoded text back to the client.
Concurrently there is a decrypt daemon that if a user sends the encrypted message and the key string the message is returned back to plain text
