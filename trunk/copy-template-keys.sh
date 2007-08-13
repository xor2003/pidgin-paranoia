#!/bin/bash
# Creates copies of the keyfile templates from the SVN
echo
echo 
echo "Please remember: The templates for the keys are from public SVN. You can use the program pad.py (branches/python-otp) to create keys."
echo
echo  Hit Enter to continue....
read

copyfiles() {

for s in $SRC; do
	for d in $DST; do
            if [ $s = $d ]; then
		#echo Source == Dest: I use the self template
		cp loop.entropy "$DIR $s $d 11111111.entropy"
	    else
		#echo Source <> Dest: I use the normal templates
		cp template.entropy "$DIR$s $d 22222222.entropy"
		cp template-rev.entropy "$DIR$d $s 22222222.entropy"
            fi
	#echo $s $d
	done
done

}

DIR="$HOME/.paranoia/"

mkdir $DIR


SRC="simon.wenner@gmail.com alexapfel@gmail.com alexapfel@swissjabber.ch nowic@swissjabber.ch"
DST=$SRC

copyfiles

SRC="alice@jabber.org bob@jabber.org"
DST=$SRC

copyfiles

SRC="76239710 112920906"
DST=$SRC

copyfiles

SRC="fredibraatsmaal@hotmail.com"
DST=$SRC

copyfiles

echo
echo "Done! Your keys are stored in $DIR".
echo


