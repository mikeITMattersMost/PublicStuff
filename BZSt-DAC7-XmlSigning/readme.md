# Purpose
Powershell script to sign a DAC7 XML file for submitting it to the german "Bundeszentralamt fuer Steuern" via DIP mass data interface (see https://www.bzst.de/DE/Service/Portalinformation/Massendaten/DIP/dip.html and https://www.bzst.de/SharedDocs/Kurzmeldungen/DE/2024_Kurzmeldungen/20240122_dac7_neues_KHB.html?nn=122794).

.net code for registering RSA-MGF1 as crypto algorithm was taken from https://stackoverflow.com/questions/22658526/rsassa-pss-without-parameters-using-sha-256-net-4-5-support

Key material must be generated with

`openssl genpkey -algorithm RSA -out pk.pem -pkeyopt rsa_keygen_bits:4096`

`openssl req -x509 -new -key pk.pem -out certificate.pem -days 3650 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32`

Can also be adopted to generally sign XML with SHA256-MGF1. Free to use without any warranty.
