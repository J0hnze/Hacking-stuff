#! /bin/bash
mkdir $HOME/tools && cd $HOME/tools &&\
git clone https://github.com/projectdiscovery/nuclei.git && \
cd nuclei/cmd/nuclei && go build && \
sudo mv nuclei /usr/local/bin/ && nuclei -version
