#wget https://hosts.nfz.moe/full/hosts -O neohosts.acl
wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts -O stevenhosts.acl
wget "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext" -O pglyoyo.acl

cat pglyoyo.acl stevenhosts.acl   | sed 's/^\#.*//g' | sed '/^ *$/d' | sed '/^$/d' | \
sed 's/\./\\\./g' | sed 's/$/\$/g' | sed 's/^\:\:1.*//g' | sed 's/^fe[0-9][0-9]\:\:.*//g' | \
sed 's/^ff[0-9][0-9]\:\:.*//g' | sed 's/^255\.255\.255\.255.*//g' |sed 's/127\\.0\\.0\\.1 /(^|\\.)/' | \
sed 's/0\\.0\\.0\\.0 /(^|\\.)/' | sed 's/\:\: /(^|\\.)/' | sed 's/\n\$/\$/' | \
uniq  > ad_temp.acl

#sort ad_temp.acl | uniq  | sed 's/^\#.*//g' | sed '/^ *$/d' | sed '/^$/d' | \
#sed 's/\./\\\./g' | sed 's/$/\$/g' | sed 's/0\\.0\\.0\\.0 /(^|\\.)/' | \
# sed 's/\:\: /(^|\\.)/' | sed 's/\n\$/\$/' > ad_temp2.acl

#sed -i '/^ *$/d' neohosts.acl
#sed -i '/^$/d' neohosts.acl
#sed -i 's/\./\\\./g' neohosts.acl
#sed -i 's/$/\$/g' neohosts.acl
#sed -i 's/0\\.0\\.0\\.0 /(^|\\.)/' neohosts.acl
#sed -i 's/\:\: /(^|\\.)/' neohosts.acl
#sed -i 's/\n\$/\$/' neohosts.acl
#sed -i '1,14d' neohosts.acl

#sed -i '/^ *$/d' stevenhosts.acl
#sed -i 's/\./\\\./g' stevenhosts.acl
#sed -i 's/$/\$/g' stevenhosts.acl
#sed -i 's/0\\.0\\.0\\.0 /(^|\\.)/' stevenhosts.acl
#sed -i '1,31d' stevenhosts.acl

#sed -i '/^ *$/d' pglyoyo.acl
#sed -i 's/\./\\\./g' pglyoyo.acl
#sed -i 's/$/\$/g' pglyoyo.acl
#sed -i 's/127\\.0\\.0\\.1 /(^|\\.)/' pglyoyo.acl
#sed -i '1,13d' pglyoyo.acl

cat myad.acl  ad_temp.acl | sort -u | uniq > ad_tmp.acl
cat myad.acl | sort -u | uniq> light_ad_tmp.acl
cat adstart.acl ad_temp.acl > ad.acl
cat adstart.acl light_ad_tmp.acl > light_ad.acl
rm ad_temp.acl pglyoyo.acl stevenhosts.acl ad_tmp.acl light_ad_tmp.acl

