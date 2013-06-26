#!/bin/sh

set -e

usage()
{
    echo "This script will create a new virtualenv on the given folder"
    echo " Usage:"
    echo "  bootstrap.sh [<DEST_DIR>]"
    echo
    echo "Where:"
    echo "  DEST_DIR is directory where the environment will be created."
    echo "  by default will be venv subdir of your current folder"
    exit 1
}

if [ "$#" -gt 1 ]; then
    usage
fi


# Retry a command for 3 times before failing
retry()
{
   tries=3
   status=1
   while [ true ] ; do
      set +e
      $@
      status=$?
      set -e

      [ $status -eq 0 ] && return

      tries=$(($tries - 1))
      if [ $tries -gt 0 ] ; then
          echo "\nCommand failed ($status), retrying...\n"
      else
          exit $status # fail
      fi
   done
}

# Expand a relative dir
expand_path()
{
    cd "$1" 2>/dev/null || return $?
    echo "`pwd -P`"
}


env=$(pwd)
# Destination dir, where to create the virtualenv
if [ "$#" -eq 0 ]; then
    dest=$(basename `expand_path ..`)
else
    dest=$1
fi

# Install build dependencies:
PKGSTOINSTALL=""
for DEP in `cat $env/build_depends.txt`; do
    if ! dpkg -l | grep -q "^ii  $DEP"; then
         PKGSTOINSTALL="$PKGSTOINSTALL $DEP"
    fi
done

if [ "$PKGSTOINSTALL" != "" ]; then
    echo "I need to apt-get install $PKGSTOINSTALL:"
    sudo apt-get install -y $PKGSTOINSTALL
fi

# Create the virutalenv
virtualenv --distribute $dest

# Activate virtualenv
cd $dest
. bin/activate

# Install requirements file
echo "Installing dependencies"
retry pip install --use-mirrors --download-cache=$PIP_CACHE -r $env/requirements.txt

if [ "$?" -eq 0 ]; then
    if [ $_ != $0 ]; then
        cd ../..
        echo
        echo
        echo "Environment set, have fun"
        echo
    else
        echo
        echo
        echo "================================================================"
        echo "Virtualenv created!. Now you should execute:"
        echo "  $ source $dest/bin/activate"
        echo "----------------------------------------------------------------"
        echo "To execute unit test, just use nosetests on root folder"
        echo "================================================================"
        echo
    fi
fi
