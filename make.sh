#!/bin/bash
sudo rmmod firewall
sudo make clean
sudo make
sudo make install
cd ./webctl
npm install
node app.js

