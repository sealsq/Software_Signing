# Software_Signing

## Launch Software_Signing Application
**On your raspberry**

clone this Repo :

    git clone https://github.com/sealsq/Software_Signing.git

update submodules

    git submodule update --init --recursive

We write scripts to simplify compilation, so make them executable

    chmod +x configure.sh

Update informations in configuration file

    nano data/inesConfig.ini

Update package to verify

    data/Signed_Software_Package

Execute the program

    sudo ./build/softwareSigning_demo -c data/inesConfig.ini