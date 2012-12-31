#!/bin/sh

help()
{
	echo "flvget.sh option <url>"
	echo "-o ouput file";
	exit;
}

while [ $# -ne 0 ];
do
	case "$1" in
		-h| -H) help; shift 1;;
		-o| -O) OUTPUT=$2; shift 2;;
		-*) echo "error: no such option $1. -h for help"; exit 1;;
		*) URL=$1; break;
	esac
done;

if [ -z $URL ];
then
	echo "argument is incorrent!";
	exit 1;
fi;

echo -n $1 | sed 's@http://@http:##@' > swf_url.txt
base64 -w0 swf_url.txt > swf_url.txt.b64
rm -f swf_url.txt

wget -O flv_get_url.txt "http://www.flvxz.com/getFlv.php?url=`cat swf_url.txt.b64`"
rm -f swf-url.txt.b64

#wget -O flv_get_list.txt `cat flv_get_url.txt | sed "s/.*'\(.*\)'.*/\1/"`
#rm -f flv_get_url.txt

cat << EOF > digurl.sed
:a; h;
s@^[^<]*<a\s*[^>]*\s*href\s*=\s*['"]*\(http://[^> "']*\)[^>]*>.*@\1@p;
g;
s@<[a-zA-Z/][a-zA-Z]*[^>]*>@@;
t a;
/<[a-zA-Z\/][a-zA-Z]*[^>]*$/{N; b a; };
d; 
EOF

sed -f digurl.sed flv_get_url.txt > flv_file_list.txt;
rm -f flv_get_list.txt

if [ -z "$OUTPUT" ];
then 
	let major=1;
	while [ -r $major.0.flv ];
   	do
	   	let major=$major+1;
   	done;
	OUTPUT="$major";
fi;

let minor=0;

for url in `sed '1d;/&hd=/d;' flv_file_list.txt`;
do
	wget --user-agent "Mozilla/1.0" -O "$OUTPUT.$minor.flv" "$url";
	let minor=$minor+1;
done;

