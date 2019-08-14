cat myad.acl | sed "s/\.\*\\\.//g" | sed "s/\^//g" | sed "s/\.\*//g" | sed "s/(|\\\.)//g" | sed "s/\\\./\./g" | sed "s/\\$//g" > surfboard_ad.conf
