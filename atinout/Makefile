#
# Copyright (C) 2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Abandoned in 2014
# It's working, but too limited in it's functions to be part of Entware

include $(TOPDIR)/rules.mk

PKG_NAME:=atinout
PKG_VERSION:=0.9.1-20141206
PKG_REV:=4976a6cb5237373b7e23cd02d7cd5517f306e3f6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://git.code.sf.net/p/atinout/code
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/atinout
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=Terminal
	TITLE:=echoing AT commands
	URL:=https://github.com/simonvetter/atinout
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/atinout/description
 AT commands as input are sent to modem and responses given as output.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -DVERSION=\"$(PKG_VERSION)\" $(TARGET_LDFLAGS) -s \
	    -o $(PKG_BUILD_DIR)/$(PKG_NAME) $(PKG_BUILD_DIR)/$(PKG_NAME).c
endef

define Package/atinout/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/opt/bin
endef

$(eval $(call BuildPackage,atinout))
