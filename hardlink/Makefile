#
# Copyright (C) 2011-2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# The newer versions requires pcre2

include $(TOPDIR)/rules.mk

PKG_NAME:=hardlink
PKG_VERSION:=1.3-20170216
PKG_REV:=e66999f5a0bf68471c0d5ee272611f38e38d40ae
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://pagure.io/hardlink.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/hardlink
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=Filesystem
	TITLE:=a tool used to create a tree of hard links
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/hardlink/description
 hardlink is the Fedora tool used to create a tree of hard links.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) \
	    $(TARGET_LDFLAGS)-s  \
	    -o $(PKG_BUILD_DIR)/hardlink $(PKG_BUILD_DIR)/hardlink.c;
endef
# -I$(STAGING_DIR)/opt/include \
# -s -L$(STAGING_DIR)/opt/lib -lpcre
define Package/hardlink/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hardlink $(1)/opt/bin
endef

$(eval $(call BuildPackage,hardlink))
