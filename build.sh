#!/bin/bash
sudo rmmod firewall
sudo make
sudo make install
cd ./webctl
node app.js

