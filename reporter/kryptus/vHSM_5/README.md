# Accessing the kNET HSM via Kryptus' solutions

To access the kNET HSM through the kNET Graphical User Interface, kkmip or
or the se_app_manager, connect to it on port 49193.


# Accessing the kNET HSM via KMIP

As specified by the KMIP protocol, commands may be sent to the kNET HSM either as
raw TTLV messages or as a HTTPS request. Please refer to `KMIP_Protocol_Overview.pdf`
for the differences between both modes.

* Raw TTLV connections must be made to kryptus.dyndns.biz, on port 49192
* HTTPS requests must be made to https://kryptus.dyndns.biz:49193/kmip


# kNET Authentication Credentials

Along with this README, you should have received two key pairs:

* **user1.key:** User 1 private key
* **user1.crt:** User 1 self-signed certificate
* **user2.key:** User 2 private key
* **user2.crt:** User 2 self-signed certificate

Those keys are registered to the only two users that were created on the HSM. Both
users are identical, but objects created by one won't be visible by the other.


# Available Ports for Applications

When uploading a Secure Execution Application, the external port that it will be
assigned must be supplied.

That port must be in the range [49194, 49201].


# About HSM's certificates

As the kNET is still on development, there's no way to set a HSM's host.
Therefore, its certificate has an invalid Common Name.

Beware of that fact when connecting to it! If the application tries to verify the
Common Name, it will fail. Thus:

* If the flag `--insecure` is supplied to `curl`, it will work normally
* kkmip requires `verify` to be set to `False` when initializing a new Client

