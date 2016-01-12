#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Some syscalls and socket flags are abset on 2.6.22.
# http://pastebin.com/PP2XMidW

include $(TOPDIR)/rules.mk

PKG_NAME:=msd_lite
PKG_VERSION:=1.08
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.netlab.linkpc.net/download/software/msd/lite
PKG_MD5SUM:=2d5f7ccc71eba7af191154f4f3496d33

include $(INCLUDE_DIR)/package.mk

define Package/msd_lite
	SECTION:=multimedia
	CATEGORY:=Multimedia
	DEPENDS:=+libpthread
	TITLE:=Multi Stream daemon Lite
	URL:=http://www.netlab.linkpc.net/wiki/en:software:msd:lite
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/msd_lite/description
 This is a light version of IPTV HTTP streaming daemon.
endef

TARGET_LDFLAGS += \
	-lssp

define Package/msd_lite/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/msd_lite $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/msd_lite.conf $(1)/opt/etc
	$(INSTALL_BIN) ./files/S94msd_lite $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,msd_lite))
