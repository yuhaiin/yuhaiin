// Package openvpn is the OpenVPN engine: the client session and the multi-client
// server that the public openvpn package configures.
//
// It sits on the packages beneath it -- wire (the packet codec), reliable (the
// control channel's acknowledgement layer), control (the TLS-carrying channel
// itself), tlswrap (--tls-auth and --tls-crypt), keys (key method 2) and data
// (the GCM and CBC data channels) -- and on dataplane's pump for the data path.
// It parses no profiles: ClientConfig and ServerConfig arrive with key material
// read and the server resolved, which is the public package's job.
package openvpn
