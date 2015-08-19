#!/bin/sh

rm -f obsolete.txt not-obsolete.txt weak.txt not-weak.txt


# Obsolete (or useless for us)

grep '^\([^:]*\):\([^:]*\):\([^:]*\):KRB5:' ciphersuites.txt > krb5.txt
grep '^\([^:]*\):\([^:]*\):DH:' ciphersuites.txt > dh.txt
grep '^\([^:]*\):\([^:]*\):ECDH:' ciphersuites.txt > ecdh.txt
grep '^\([^:]*\):\([^:]*\):\([^:]*\):PSK:' ciphersuites.txt > psk.txt
grep '^\([^:]*\):\([^:]*\):SRP:' ciphersuites.txt > srp.txt
grep '^\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):IDEA:' ciphersuites.txt > idea.txt

sort -u krb5.txt dh.txt ecdh.txt psk.txt srp.txt idea.txt > obsolete.txt
grep -f obsolete.txt -v ciphersuites.txt > not-obsolete.txt
rm -f krb5.txt dh.txt ecdh.txt idea.txt psk.txt srp.txt


# Weak

grep :0002 not-obsolete.txt > sslv2.txt
grep :true: not-obsolete.txt > export.txt
grep :DES: not-obsolete.txt > des.txt
grep '^\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):NULL:' not-obsolete.txt > eNULL.txt
grep '^\([^:]*\):\([^:]*\):\([^:]*\):NULL:' not-obsolete.txt > aNULL.txt

sort -u sslv2.txt export.txt des.txt eNULL.txt aNULL.txt > weak.txt
grep -f weak.txt -v not-obsolete.txt > not-weak.txt
rm -f not-obsolete.txt sslv2.txt sslv2.txt export.txt des.txt eNULL.txt aNULL.txt



# Acceptable

grep :RC4: not-weak.txt > rc4.txt
grep :3DES: not-weak.txt > 3des.txt
grep :DSS: not-weak.txt > dss.txt
grep :HMAC-MD5: not-weak.txt > md5.txt

sort -u rc4.txt 3des.txt dss.txt md5.txt > acceptable.txt
grep -f acceptable.txt -v not-weak.txt > strong.txt
rm -f not-weak.txt rc4.txt 3des.txt dss.txt md5.txt



(
    while read line; do echo "$line":O:0; done < obsolete.txt
    while read line; do echo "$line":W:0; done < weak.txt
    while read line; do echo "$line":A:0; done < acceptable.txt
    while read line; do echo "$line":S:0; done < strong.txt
) | sed 's/^\(.*:\(ECDHE\|DHE\):.*\):0$/\1:1/; s/true/1/; s/false/0/' |
    while IFS=: read cs rem; do
        printf "%d:%s\n" 0x$cs $rem
    done > enriched-ciphersuites.csv

rm -f obsolete.txt weak.txt acceptable.txt strong.txt
