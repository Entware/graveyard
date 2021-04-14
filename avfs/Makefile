#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Uses Perl to mount external filesystems, won't fix it

include $(TOPDIR)/rules.mk

PKG_NAME:=avfs
PKG_VERSION:=1.1.4
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@SF/avf/$(PKG_NAME)/$(PKG_VERSION)
PKG_HASH:=3a7981af8557f864ae10d4b204c29969588fdb526e117456e8efd54bf8faa12b

#PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/avfs
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=Filesystem
	TITLE:=A Virtual FileSystem
	URL:=http://avf.sourceforge.net/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/avfs/description
 AVFS is a system, which enables all programs to look inside
 gzip, tar, zip, etc. files or view remote (ftp, http, dav, etc.) files,
 without recompiling the programs.
endef

define Package/avfs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/avfsd $(1)/opt/bin
endef

$(eval $(call BuildPackage,avfs))
