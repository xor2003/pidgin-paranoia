#!/bin/bash
# Creates copies of the keyfile templates from the SVN
echo
echo 
echo "Please remember: The templates for the keys are from public SVN. Use the plugin to create keys."
echo
echo  Hit Enter to continue....
read

DIR="$HOME/.paranoia/"



copyfiles() {

for s in $SRC; do
	for d in $DST; do
		if [ $s = $d ]; then
			#echo Source == Dest: I use the self template
			I=$(($IDLOOP+$i))
			echo "$s $d $I.entropy"
			cp loop$SUFF.entropy "$DIR$s $d $I.entropy"
	    else
			I=$(($ID+$i))
			#echo Source <> Dest: I use the normal templates
			echo "$s $d $I.entropy"
			cp template$SUFF.entropy "$DIR$s $d $I.entropy"
			echo "$d $s $I.entropy"
			cp template-rev$SUFF.entropy "$DIR$d $s $I.entropy"
		fi
		i=$(($i+1))
		#echo $i
	done
done
}

makefiles() {
mkdir $DIR

# Alice and Bob

SRC="alice@jabber.org bob@jabber.org"
DST=$SRC

copyfiles

#Loop Keys....

SRC="76239710"
DST=$SRC

copyfiles

SRC="112920906"
DST=$SRC

copyfiles

SRC="fredibraatsmaal@hotmail.com"
DST=$SRC

copyfiles

SRC="nowic@swissjabber.ch"
DST=$SRC

copyfiles

SRC="alexapfel@swissjabber.ch"
DST=$SRC

copyfiles

#------------------------------------

echo
echo "Done! Your keys are stored in $DIR".
echo

}




echo "Select an action:"
OPT="large small delete EXIT"

select opt in $OPT; do
		i="0"
 	 	if [ "$opt" = "EXIT" ]; then
			exit
  		fi

 	 	if [ "$opt" = "large" ]; then
			SUFF=""	
			IDLOOP="11111100"
			ID="22222200"
			makefiles
  		fi

 	 	if [ "$opt" = "small" ]; then
			SUFF="-small"
			IDLOOP="11111150"
			ID="22222250"
			makefiles
  		fi

 	 	if [ "$opt" = "delete" ]; then
			rm $DIR/*111111* $DIR/*222222*
  		fi
		echo "Select an action:"
done


