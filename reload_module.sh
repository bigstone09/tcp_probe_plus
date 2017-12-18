#!/bin/bash
set -xu

rmmod tcp_probe_plus.ko
insmod tcp_probe_plus.ko port=80
