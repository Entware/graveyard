#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Fetches bunch of deps during Build/Compile
# Requires gcc 10.1+ to conform C++20 standard
# #include <ranges>
# #include <compare>

include $(TOPDIR)/rules.mk

PKG_NAME:=torrenttools
PKG_VERSION:=0.4.1
PKG_REV:=70d4c576c6555236e8410cdcba1c2c037edc6fc2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/fbdtemme/torrenttools.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_MIRROR_HASH:=6afe88290212eebabccc21e3d1158499767fc96dca850953a6cf70301651ba95

include $(INCLUDE_DIR)/package.mk
#include $(INCLUDE_DIR)/cmake.mk
include $(TOPDIR)/feeds/packages/devel/ninja/ninja-cmake.mk

define Package/torrenttools
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=inspecting, creating and editing BT metafiles
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/torrenttools/description
 Commandline tool for inspecting, creating and editing BitTorrent metafiles.
endef

define Package/torrenttools/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/torrenttools $(1)/opt/bin
endef

$(eval $(call BuildPackage,torrenttools))
