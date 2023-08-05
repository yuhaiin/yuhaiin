cd cn
. ./get_cn.sh
cd ..

cd yuhaiin
. ./update.sh
cd ..

git add .
git commit -m "update"
git push -u origin ACL
