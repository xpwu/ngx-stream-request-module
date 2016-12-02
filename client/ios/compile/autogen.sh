#!/bin/bash

touch NEWS README AUTHORS ChangeLog

aclocal && autoconf && automake -a
