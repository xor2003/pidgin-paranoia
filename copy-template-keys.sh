#!/bin/bash
# Creates copies of the keyfile templates from the SVN
echo
echo 
echo "Please remember: The templates for the keys are from public SVN. You can use the program pad.py (branches/python-otp) to create keys."
echo
echo  Hit Enter to continue....
read

echo "Select the size of your templates:"
OPT="large small EXIT"
select opt in $OPT; do
 	 	if [ "$opt" = "EXIT" ]; then
			exit
  		fi

 	 	if [ "$opt" = "large" ]; then
			SUFF=""	
			IDLOOP="11111111"
			ID="22222222"
			break
  		fi

 	 	if [ "$opt" = "small" ]; then
			SUFF="-small"
			IDLOOP="1111111F"
			ID="2222222F"
			break
  		fi
		exit
done


copyfiles() {

for s in $SRC; do
	for d in $DST; do
            if [ $s = $d ]; then
		#echo Source == Dest: I use the self template
		cp loop$SUFF.entropy "$DIR$s $d $IDLOOP.entropy"
	    else
		#echo Source <> Dest: I use the normal templates
		cp template$SUFF.entropy "$DIR$s $d $ID.entropy"
		cp template-rev$SUFF.entropy "$DIR$d $s $ID.entropy"
            fi
	#echo $s $d
	done
done

}

DIR="$HOME/.paranoia/"

mkdir $DIR
rm $DIR/*


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


