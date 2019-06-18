/*
The uua library may be used for generating API-key - like tokens to grant to users.

You may create and serialize tokens for later verification. Token content is encrypted, so sensitive information is not exposed (e.g., app names, current library version, or generation number). And the encrypted content is signed with a private key, to guard against tampering.
*/
package uua
