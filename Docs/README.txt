Forudsætninger
==============

OOAPI.NET kræver .NET 3.5SP1.

Hvis følgende fejl opleves:

   System.Security.Cryptography.CryptographicException : Object identifier (OID) is unknown.
   at System.Security.Cryptography.X509Certificates.X509Utils._GetAlgIdFromOid(String oid)
   at System.Security.Cryptography.X509Certificates.X509Utils.OidToAlgId(String oid)
   at System.Security.Cryptography.RSACryptoServiceProvider.VerifyHash(Byte[] rgbHash, String str, Byte[] rgbSignature)
   ...
   
så kør den vedlagte RegisterSha2.exe.


For at køre tests skal NUnit installeres
========================================

For at kunne køre PidAliveTesterTest eller lave pid/cpr-tjek fra browseren, skal man importere server-certifikatet
resources\x509\certificates\pidservice-oces1systemtest.cer
og klient-certifikatet
resources\x509\certificates\Digital Signatur for OCES2 ws klient.pfx (password: Test1234)

PidServiceTest er udkommenteret, da den kræver en PID-service kørende lokalt på maskinen. Har man det, skal
man yderligere importere certifikatet resources\certificates\pidservice-localhost.cer som ligger i
test-projektet.


For at lave dokumentation
=========================

For at lave dokumentation skal man have følgende to produkter installeret:

+ Sandcastle - Version 2.4.10520 (eller nyere)
+ HTML Help Workshop and Documentation 1.32 (eller nyere)

Man skal køre msbuild scriptet

msbuild doc.scproj

i biblioteket ooapi.net\trunk\ooapi.net.

Man kan sætte Configuration parameteren på men som default er Configuration Debug.

msbuild doc.scproj /p:Configuration=Release

Resultatet kan ses enten i bin/Release/ooapi.chm eller bin/Debug/ooapi.chm

For at køre tuexample.net
=========================

Det kræves at man i web.config i key'en pfxFile angiver stien til "korrektCSPpfxname.pfx" som ligger under Docs/. Password for denne er Test1234.
Hvis det ikke virker kan man med fordel undersøge om følgende sti findes i registerings databasen:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Enhanced RSA and AES Cryptographic Provider

Hvis den ikke findes er der behov få at få fat i den CSP. For windows xp kræves at man benytter SP3. Desuden er det set under windows xp at CSP'en ikke hedder:

"Microsoft Enhanced RSA and AES Cryptographic Provider" men derimod "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)". 
I det tilfælde skal man i stedet i web.config key'en pfxFile angive stien til "korrektCSPwPrototypepfxname.pfx" som ligeledes ligger under Docs/. Password for denne er Test1234.

Alternativt kan man selv lave en ny pfx fil. Som bliver beskrevet nedenstående hvor man angiver:
"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)" i kommandoen til openssl.


Hvordan man laver pfx fil til korrekt CSP.
==========================================

Hvis man har en pfx fil som har forkert CSP navn. Kan man med fordel benytte sig af PfxCspFixer.exe. Ved at benytte dette program vil man få oprettet en ny pfx med samme password.
Men hvor CSP er blevet sat til "Microsoft Enhanced RSA and AES Cryptographic Provider".

Start programmet. Programmet spørger dig så om stien til oprindelig pfx fil samt password. Herefter oprettes der en ny pfx som har samme navn som den oprindelig blot med et 
"correctCsp" prepended. dvs:

some.pfx bliver til correctCspsome.pfx.

Hvordan laver man en pfx udfra et jks.
======================================

Man kan med fordel benytte keytool som findes i java 6. Keytool findes også i tidligere version af java, men der understøttes import og eksport af privatnøgler ikke.

Kør først følgende kommando:

keytool -list -rfc -keystore keystore.jks

Dette vil efter man har angivet password liste de certifikat og tilhørende privatnøgler. Efter at have fundet det man gerne vil exporte skal man se hvilket alias det ligger under.

Det vil se ud noget ala følgende:


Keystore type: JKS
Keystore provider: SUN

Alias name: alias
Creation date: Feb 2, 2010
Entry type: PrivateKeyEntry
Certificate chain length: 2
Certificate[1]:
-----BEGIN CERTIFICATE-----
MIIE/jCCBGegAwIBAgIEQDdyTjA
...
-----END CERTIFICATE-----


*******************************************
*******************************************


Alias name: certsign
Creation date: Feb 4, 2010
Entry type: trustedCertEntry

-----BEGIN CERTIFICATE-----
MIIC/zCCAeegA...

I ovenstående eksempel er det Alias name man skal have fat i "alias" da "certsign" blot er et trustet certifikat og ikke en privatnøgle.

Ved derefter at benytte sig af følgende kommando kan man få lavet en pfx fil.

keytool -importkeystore -srckeystore keystore.jks -srcalias "alias" -destkeystore cert.pfx -deststoretype pkcs12

Nu har man en pfx fil ved navn "cert.pfx". Denne pfx har dog stadig det forkerte CSP navn. Så derfor skal efterfølgende følge guiden "Hvordan man laver pfx fil til korrekt CSP".

