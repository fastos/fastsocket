#!/bin/bash

set -e

case "$1" in
	config)
		echo "Configuring..."
		pushd config
		cmake .
		make
		popd
		config/conf Kconfig
		cmake .
	;;

	compile)
		echo "Compile time..."
		make
	;;

	install)
		if [ ! -e .config ]; then
			exit 1
		fi

		. ./.config
		make

		echo -n "Installing firmware..."
		if [ "$CONFIG_CARL9170FW_BUILD_TOOLS" = "y" ] &&
		   [ "$CONFIG_CARL9170FW_BUILD_MINIBOOT" = "y" ]; then
			echo -n "Apply miniboot..."
			tools/src/miniboot a carlfw/carl9170.fw minifw/miniboot.fw
		fi

		install -m 644 carlfw/carl9170.fw \
			../carl9170-$CONFIG_CARL9170FW_RELEASE_VERSION.fw
		echo "done."
	;;

	*)
		$0 config
		$0 compile
	;;


esac
