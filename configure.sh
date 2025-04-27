#!/bin/bash -e
#=======================================
#SEAL SQ 2024
#Zero Touch Provisioning Demo with INeS
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

############################################################
# Help                                                     #
############################################################
FIRST_CONFIG_FILE=.firstconfig.txt

Help()
{
   # Display Help
   echo "This script allow you to run instalation and working SealSQ Software Signing Demo"
   echo "If you want to reexecute first install, remove .firstconfig.txt files"

   echo
}

checkoutLibs()
{   
   pushd "lib/Seal_SQ_Ines_SDK"
   #echo "----------| Checkout to INeS VERSION : ${INES_SDK_TAG} |----------"
   #git checkout ${INES_SDK_TAG}   
   popd
}

install()
{
   sudo apt-get update
   sudo apt-get --yes --force-yes install cmake	
   sudo apt-get --yes --force-yes install python3
   configurelib
   checkoutLibs
   echo done, remove this file if you want to do first setup again > ${FIRST_CONFIG_FILE}


}

configurelib()
{
   echo "---Software Signing: Configure ZTP lib START---"
   pushd lib/Seal_SQ_Ines_SDK/
   
   chmod +x build.sh
   ./build.sh
   popd
   echo "---Software Signing: Configure ZTP lib END---"

}

buildapp()
{
   echo "---Software Signing: Build APP START---"
   source lib/Seal_SQ_Ines_SDK/config.cfg

   CMAKE_OPTS="-DVAULTIC_PRODUCT=${VAULTIC_PRODUCT}"
   
   CMAKE_OPTS+=" -DWOLFSSL_USER_SETTINGS=yes -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no"
   
   if([ ! -z ${COMPILATION_MODE} ] ); then 
    CMAKE_OPTS+=" -DCOMPILATION_MODE=${COMPILATION_MODE}"
   fi

   if([ ! -z ${INTERFACE} ] ); then 
    CMAKE_OPTS+=" -DVAULTIC_COMM=${INTERFACE}"
   fi

   echo "Running CMAKE"
   rm -rf build/
   mkdir build
   cd build/
   cmake ${CMAKE_OPTS} ..
   echo "Cleaning"
   make clean
   echo "Building"
   make all

   if [ -f "./softwareSigning_demo" ];then
      echo "Software Signing_demo App in C build";
   else
      exit
   fi
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################
############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options

while getopts ":hbizg" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      b) # Force building
	   echo "force building"
         buildapp
         exit;;
      i) # Install Prerequities
		 echo "Install Requierment"
         install
         exit;;
      g) # Git checkouts
		 echo "Install Requierment"
         checkoutLibs
         exit;;
      \?) # Invalid option
         echo "Error: Invalid option"
         Help
         exit;;
   esac
done

echo "Software Signing Demo Configuration and Building"
if [ -e ${FIRST_CONFIG_FILE} ]
then
    echo "First config Already done"
else
    echo "Do first config"
    install
fi


buildapp